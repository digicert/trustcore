/*
 * Trust Anchor Platform utility function APIs
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

#ifdef __RTOS_WIN32__
#include <ShlObj.h>
#include <Shlwapi.h>
#endif /*  __RTOS_WIN32__ */

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mprintf.h"
#include "../common/mtcp.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/prime.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../common/moc_config.h"
#include "../common/base64.h"
#include "../common/mfmgmt.h"
#include "../crypto/hw_accel.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/ca_mgmt.h"
#endif

#include "tap_common.h"
#include "tap_api.h"
#include "tap_client_comm.h"
#include "tap_utils.h"
#include "tools/moctap_credparser.h"

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../data_protection/file_protect.h"
#endif

#ifdef __ENABLE_DIGICERT_TEE__
#include "../common/utils.h"
#define DIGICERT_readFile UTILS_readFile
#endif

#ifdef __RTOS_WIN32__
 /* Path relative to %PogramData% */
#define MOCANA_APPDATA_DIR_NAME    "Mocana"
#endif /*  __RTOS_WIN32__ */

/**
 * @ingroup tap_definitions
 * @details Human readable names corresponding to #TAP_PROVIDER values.
 */
 /* This must stay in sync with the #TAP_PROVIDER definitions in tap_smp.h */
static char *pTapProviderNames[] =
{
    "Undefined",
    "Software",
    "TPM 1.2",
    "TPM 2.0",
    "SGX",
    "STSAFE",
    "Gemalto SIM",
    "Renesas S5",
    "TrustX",
    "ARM M23",
    "ARM M33",
    "EPID",
    "TEE",
    "PKCS11",
    "NXPA71",
    "NanoROOT"
};

#ifndef __ENABLE_TAP_REMOTE__
extern MSTATUS
MocTap_GetCredentialData( sbyte* scriptContent, sbyte4 scriptLen, 
      TAP_EntityCredentialList **pUsageCredentials);
#endif

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TAP_UTILS_freeBuffer(TAP_Buffer *pBuffer)
{
    MSTATUS status = OK;

    if (NULL == pBuffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pBuffer->pBuffer)
    {
        status = DIGI_FREE((void **)&(pBuffer->pBuffer));
        pBuffer->bufferLen = 0;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyBufferOffset(
    TAP_Buffer *pDestBuffer,
    TAP_Buffer *pSrcBuffer,
    ubyte4 offset)
{
    MSTATUS status = OK;

    if ((NULL == pDestBuffer) || (NULL == pSrcBuffer))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pSrcBuffer->bufferLen) || (NULL == pSrcBuffer->pBuffer))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    if (offset >= pSrcBuffer->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid offset %d for buffer length %d\n", __FUNCTION__,
                __LINE__, offset, pSrcBuffer->bufferLen);
        goto exit;
    }


    status = DIGI_CALLOC((void **)&(pDestBuffer->pBuffer), 1, pSrcBuffer->bufferLen - offset);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for pDestBuffer. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_MEMCPY(pDestBuffer->pBuffer, pSrcBuffer->pBuffer + offset,
                        pSrcBuffer->bufferLen - offset);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pDestBuffer. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pDestBuffer->bufferLen = pSrcBuffer->bufferLen - offset;

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyBuffer(TAP_Buffer *pDestBuffer, TAP_Buffer *pSrcBuffer)
{
    return TAP_UTILS_copyBufferOffset(pDestBuffer, pSrcBuffer, 0);
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeBlob(TAP_Blob *pBlob)
{
    MSTATUS status = OK;

    if (NULL == pBlob)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pBlob->blob.pBuffer)
    {
        status = TAP_UTILS_freeBuffer(&(pBlob->blob));
    }
    pBlob->format = 0;
    pBlob->encoding = 0;

exit:

    return status;
}
/*------------------------------------------------------------------*/


MSTATUS TAP_UTILS_copyBlob(TAP_Blob *pDestBlob, TAP_Blob *pSrcBlob)
{
    MSTATUS status = OK;

    if ((NULL == pDestBlob) || (NULL == pSrcBlob))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(&(pDestBlob->blob), &(pSrcBlob->blob));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for pDestBlob->blob. status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pDestBlob->format = pSrcBlob->format;
    pDestBlob->encoding = pSrcBlob->encoding;

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeConfigInfoList(TAP_ConfigInfoList *pConfigInfoList)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    if (NULL == pConfigInfoList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pConfigInfoList->pConfig)
    {
        /* TODO: Should we error here, or just exit with nothing to free? */
        goto exit;
    }

    for (i = 0; i < pConfigInfoList->count; i++)
    {
        if (NULL != pConfigInfoList->pConfig[i].configInfo.pBuffer)
        {
            status = TAP_UTILS_freeBuffer(&(pConfigInfoList->pConfig[i].configInfo));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to free configInfo list %d. status %d = %s\n", __FUNCTION__,
                        __LINE__, i, status, MERROR_lookUpErrorCode(status));
            }
        }
    }
    status = DIGI_FREE((void **) &(pConfigInfoList->pConfig));

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeProviderList(TAP_ProviderList *pProviderList)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    if (NULL == pProviderList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pProviderList->pProviderCmdList)
    {
        /* TODO: Should we error here, or just exit with nothing to free? */
        goto exit;
    }

    for (i = 0; i < pProviderList->listLen; i++)
    {
        if (NULL != pProviderList->pProviderCmdList[i].cmdList.pCmdList)
        {
            status = DIGI_FREE((void **)&pProviderList->pProviderCmdList[i].cmdList.pCmdList);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to free command list for provider %d. status %d = %s\n", __FUNCTION__,
                        __LINE__, i, status, MERROR_lookUpErrorCode(status));
            }
            pProviderList->pProviderCmdList[i].cmdList.pCmdList = NULL;
            pProviderList->pProviderCmdList[i].cmdList.listLen = 0;
        }
    }

    if (NULL != pProviderList->pProviderCmdList)
    {
        status = DIGI_FREE((void **)&(pProviderList->pProviderCmdList));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free provider command list. status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
        }
        pProviderList->listLen = 0;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_getProviderListLen(TAP_ProviderList *pList, ubyte4 *pListLen)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    if ((NULL == pList) || (NULL == pListLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pListLen = 0;

    if ((0 >= pList->listLen) || (NULL == pList->pProviderCmdList))
    {
        goto exit;
    }

    /* Account for listLen in TAP_PoviderList */
    *pListLen +=  sizeof(ubyte4);
    /* Loop through pProviderCmdList elements */
    for (i = 0; i < pList->listLen; i++)
    {
        *pListLen += sizeof(TAP_PROVIDER);
        /* listLen in TAP_CmdCodeList */
        *pListLen += sizeof(ubyte4);
        /* pCmdlist in TAP_CmdCodeList */
        *pListLen += pList->pProviderCmdList[i].cmdList.listLen * sizeof(SMP_CC);
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyTapModule(TAP_Module *pDestModule, TAP_Module *pSrcModule) 
{
    MSTATUS status = OK;

    if ((NULL == pDestModule) || (NULL == pSrcModule))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDestModule->providerType = pSrcModule->providerType;

    /* copy TAP_ModuleId */
    pDestModule->moduleId = pSrcModule->moduleId;
    /* copy TAP_ConnectionInfo */
    pDestModule->hostInfo.serverName.bufferLen = pSrcModule->hostInfo.serverName.bufferLen;
    if (0 < pDestModule->hostInfo.serverName.bufferLen)
    {
        status = DIGI_CALLOC((void **)&(pDestModule->hostInfo.serverName.pBuffer), 1, pDestModule->hostInfo.serverName.bufferLen);
        if (OK != status)
        {
            goto exit;
        }

        status = DIGI_MEMCPY(pDestModule->hostInfo.serverName.pBuffer,
                             pSrcModule->hostInfo.serverName.pBuffer,
                             pDestModule->hostInfo.serverName.bufferLen);
        if (OK != status)
        {
            goto exit;
        }
    }

    pDestModule->hostInfo.serverPort = pSrcModule->hostInfo.serverPort;

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeTapModule(TAP_Module *pModule) 
{
    MSTATUS status = OK;

    if (NULL == pModule)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pModule->hostInfo.serverName.pBuffer)
    {
        status = DIGI_FREE((void **)&(pModule->hostInfo.serverName.pBuffer));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free memory for module serverName. status %d = %s\n", __FUNCTION__,
                   __LINE__, status, MERROR_lookUpErrorCode(status));
        }
    }

    status = DIGI_MEMSET((ubyte *)pModule, 0, sizeof(TAP_Module));

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeModuleList(TAP_ModuleList *pList)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    if (NULL == pList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pList->numModules) || (NULL == pList->pModuleList))
    {
        goto exit;
    }

    for (i = 0; i < pList->numModules; i++)
    {
        /* Free the serverName buffer, then clear the rest */
        if (NULL != pList->pModuleList[i].hostInfo.serverName.pBuffer)
        {
            status = TAP_UTILS_freeBuffer(&(pList->pModuleList[i].hostInfo.serverName));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to free memory for serverName. status %d = %s\n", __FUNCTION__,
                       __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
            status = DIGI_MEMSET((ubyte *)&(pList->pModuleList[i]), 0, sizeof(TAP_Module));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to memset memory for module list. status %d = %s\n", __FUNCTION__,
                       __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
    }
    status = DIGI_FREE((void **)&(pList->pModuleList));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free memory for module list. status %d = %s\n", __FUNCTION__,
               __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pList->numModules = 0;
    status = OK;

exit:

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS TAP_UTILS_copyCredential(TAP_Credential *pDestCredentials,
        TAP_Credential *pSrcCredentials)
{
    MSTATUS status = OK;

    pDestCredentials->credentialType = pSrcCredentials->credentialType;
    pDestCredentials->credentialFormat = pSrcCredentials->credentialFormat;
    pDestCredentials->credentialContext = pSrcCredentials->credentialContext;

    /* Allocate Auth data buffer, if required */
    pDestCredentials->credentialData.bufferLen =
        pSrcCredentials->credentialData.bufferLen;

    if (pDestCredentials->credentialData.bufferLen)
    {
        status = DIGI_MALLOC(
                (void **)&pDestCredentials->credentialData.pBuffer,
                pDestCredentials->credentialData.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating memory for credential auth data, "
                    "status %d = %s\n",
                    __FUNCTION__, __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = DIGI_MEMCPY(pDestCredentials->credentialData.pBuffer,
                pSrcCredentials->credentialData.pBuffer,
                pDestCredentials->credentialData.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error copying credential auth data, "
                    "status %d = %s\n",
                    __FUNCTION__, __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS TAP_UTILS_copyCredentialList(TAP_CredentialList *pDestCredentialList,
        TAP_CredentialList *pSrcCredentialList)
{
    MSTATUS status = OK;
    ubyte4 j;

    pDestCredentialList->numCredentials =
        pSrcCredentialList->numCredentials;

    if (pDestCredentialList->numCredentials)
    {
        /* Allocate space for Credentials */
        status = DIGI_CALLOC((void **)&pDestCredentialList->pCredentialList,
                1, sizeof(pDestCredentialList->numCredentials) *
                pDestCredentialList->numCredentials);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating memory for credential list, "
                    "status %d = %s\n",
                    __FUNCTION__, __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        for (j = 0; j < pDestCredentialList->numCredentials; j++)
        {

            status = TAP_UTILS_copyCredential(&pDestCredentialList->pCredentialList[j],
                    &pSrcCredentialList->pCredentialList[j]);

            if (OK != status)
            {
                goto exit;
            }
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS TAP_UTILS_copyEntityCredentials(TAP_EntityCredential *pDestEntityCredentials,
        TAP_EntityCredential *pSrcEntityCredentials)
{
    MSTATUS status = OK;

    pDestEntityCredentials->parentType = pSrcEntityCredentials->parentType;
    pDestEntityCredentials->parentId = pSrcEntityCredentials->parentId;
    pDestEntityCredentials->entityType = pSrcEntityCredentials->entityType;
    pDestEntityCredentials->entityId = pSrcEntityCredentials->entityId;

    status = TAP_UTILS_copyCredentialList(&pDestEntityCredentials->credentialList,
            &pSrcEntityCredentials->credentialList);
    if (OK != status)
    {
        goto exit;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS TAP_UTILS_copyEntityCredentialList(TAP_Attribute *pDestAttr,
        TAP_Attribute *pSrcAttr)
{
    MSTATUS status = OK; 
    TAP_EntityCredentialList *pSrcEntityCredentialList = NULL; 
    TAP_EntityCredentialList *pDestEntityCredentialList = NULL; 
    ubyte4 i;

    pSrcEntityCredentialList = (TAP_EntityCredentialList *)pSrcAttr->pStructOfType;
    pDestEntityCredentialList = (TAP_EntityCredentialList *)pDestAttr->pStructOfType;
    pDestEntityCredentialList->numCredentials = pSrcEntityCredentialList->numCredentials;
    if (pDestEntityCredentialList->numCredentials)
    {
        /* Allocate space for Entity Credential */
        status = DIGI_CALLOC((void **)&pDestEntityCredentialList->pEntityCredentials,
                1, pDestEntityCredentialList->numCredentials * 
                sizeof(*pDestEntityCredentialList->pEntityCredentials));
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating memory for entity credential list, "
                    "status %d = %s\n", 
                    __FUNCTION__, __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit; 
        }

        for (i = 0; i < pDestEntityCredentialList->numCredentials; i++)
        {
            status = TAP_UTILS_copyEntityCredentials(&pDestEntityCredentialList->pEntityCredentials[i],
                    &pSrcEntityCredentialList->pEntityCredentials[i]);

            if (OK != status)
            {
                goto exit; 
            }
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyAttributeList(TAP_AttributeList *pDestList,
                                    TAP_AttributeList *pSrcList)
{
    MSTATUS status = OK;
    ubyte4 i = 0, j = 0;
    TAP_Buffer *pSrcTapBuffer = NULL;
    TAP_Buffer *pDestTapBuffer = NULL;
    ubyte listLen = 0;

    if ((NULL == pDestList) || (NULL == pSrcList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDestList->listLen = 0;
    pDestList->pAttributeList = NULL;

    if ((0 == pSrcList->listLen) || (NULL == pSrcList->pAttributeList))
    {
        goto exit;
    }

    listLen = pSrcList->listLen;

    for (i = 0; i < pSrcList->listLen; i++)
    {
        if (TAP_ATTR_SERIALIZED_OBJECT_BLOB == pSrcList->pAttributeList[i].type)
        {
            listLen--;
        }
    }

    status = DIGI_CALLOC((void **)&(pDestList->pAttributeList),
                         listLen, sizeof(TAP_Attribute));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for attribute list. status %d = %s\n", __FUNCTION__,
               __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pDestList->listLen = listLen;

    for (i = j = 0; i < pSrcList->listLen; i++, j++)
    {
        if (TAP_ATTR_SERIALIZED_OBJECT_BLOB == pSrcList->pAttributeList[i].type)
        {
            i++; /* skip it, move to the next one */
        }

        if ((0 != pSrcList->pAttributeList[i].length) && (NULL != pSrcList->pAttributeList[i].pStructOfType))
        {
            status = DIGI_CALLOC((void **)&(pDestList->pAttributeList[j].pStructOfType), 1,
                                 pSrcList->pAttributeList[i].length);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for attribute. status %d = %s\n", __FUNCTION__,
                       __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = DIGI_MEMCPY(pDestList->pAttributeList[j].pStructOfType,
                                pSrcList->pAttributeList[i].pStructOfType,
                                pSrcList->pAttributeList[i].length);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy memory for attribute. status %d = %s\n", __FUNCTION__,
                       __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
        else if ((0 == pSrcList->pAttributeList[i].length) && (NULL == pSrcList->pAttributeList[i].pStructOfType))
        {
            /* Null-terminated end of the list */
            pDestList->pAttributeList[j].pStructOfType = NULL;
        }
        pDestList->pAttributeList[j].length = pSrcList->pAttributeList[i].length;
        pDestList->pAttributeList[j].type = pSrcList->pAttributeList[i].type;

        switch (pSrcList->pAttributeList[i].type)
        {
            case TAP_ATTR_VENDOR_INFO:
            case TAP_ATTR_MODULE_KEY:
            case TAP_ATTR_RNG_SEED:
            case TAP_ATTR_RND_STIR:
            case TAP_ATTR_ENC_LABEL:
            case TAP_ATTR_BUFFER:
            case TAP_ATTR_TRUSTED_DATA_KEY:
            case TAP_ATTR_TRUSTED_DATA_VALUE:
            case TAP_ATTR_TEST_REPORT:
            case TAP_ATTR_TEST_REQUEST_DATA:
            case TAP_ATTR_ADDITIONAL_AUTH_DATA:
            case TAP_ATTR_OBJECT_VALUE:
            case TAP_ATTR_GET_MODULE_CREDENTIALS:
            case TAP_ATTR_OBJECT_ID_BYTESTRING:
                pSrcTapBuffer = (TAP_Buffer *)(pSrcList->pAttributeList[i]).pStructOfType;
                pDestTapBuffer = (TAP_Buffer *)(pDestList->pAttributeList[j]).pStructOfType;
                status = DIGI_MALLOC((void **)&pDestTapBuffer->pBuffer, pSrcTapBuffer->bufferLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for attribute TAP_Buffer pointer, "
                            "status %d = %s\n",
                            __FUNCTION__, __LINE__, pSrcTapBuffer->bufferLen,
                            status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }
                status = DIGI_MEMCPY(pDestTapBuffer->pBuffer, pSrcTapBuffer->pBuffer,
                        pSrcTapBuffer->bufferLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error copying attribute TAP_Buffer, "
                            "status %d = %s\n", 
                            __FUNCTION__, __LINE__, status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }
                pDestTapBuffer->bufferLen = pSrcTapBuffer->bufferLen;
                break;

            case TAP_ATTR_TRUSTED_DATA_INFO:
                /* Needs special handling */
                break;

            case TAP_ATTR_CREDENTIAL_USAGE:
                status = TAP_UTILS_copyEntityCredentialList((TAP_Attribute*)&(pDestList->pAttributeList[j]), 
                            (TAP_Attribute*)&(pSrcList->pAttributeList[i]));
                break;

            case TAP_ATTR_CREDENTIAL_SET:
                 status = TAP_UTILS_copyCredentialList((TAP_CredentialList *)pDestList->pAttributeList[j].pStructOfType,
                            (TAP_CredentialList *)(pSrcList->pAttributeList[i]).pStructOfType);
                break;

            case TAP_ATTR_ENTITY_CREDENTIAL:
                status = TAP_UTILS_copyEntityCredentials((TAP_EntityCredential *)pDestList->pAttributeList[j].pStructOfType,
                            (TAP_EntityCredential *)(pSrcList->pAttributeList[i]).pStructOfType);
                break;

            case TAP_ATTR_PUBLIC_KEY:
                 status = TAP_UTILS_copyPublicKey((TAP_PublicKey *)pDestList->pAttributeList[j].pStructOfType,
                            (TAP_PublicKey *)(pSrcList->pAttributeList[i]).pStructOfType);
                break;

            case TAP_ATTR_CREDENTIAL:
                status = TAP_UTILS_copyCredential((TAP_Credential *)pDestList->pAttributeList[j].pStructOfType,
                            (TAP_Credential *)(pSrcList->pAttributeList[i]).pStructOfType);
                break;

            default:
                break;
        }
    }

exit:

    if (OK != status)
        TAP_UTILS_freeAttributeList(pDestList);

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeAttributeList(TAP_AttributeList *pList)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    TAP_Buffer *pTapBuffer = NULL;
    TAP_EntityCredential *pEntityCredential = NULL;

    if (NULL == pList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Don't error on an empty list */
    if ((0 == pList->listLen) && (NULL == pList->pAttributeList))
    {
        goto exit;
    }

    if ((0 == pList->listLen) || (NULL == pList->pAttributeList))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    for (i = 0; i < pList->listLen; i++)
    {
        if (NULL != pList->pAttributeList[i].pStructOfType)
        {
            switch (pList->pAttributeList[i].type)
            {
                case TAP_ATTR_VENDOR_INFO:
                case TAP_ATTR_MODULE_KEY:
                case TAP_ATTR_RNG_SEED:
                case TAP_ATTR_RND_STIR:
                case TAP_ATTR_ENC_LABEL:
                case TAP_ATTR_BUFFER:
                case TAP_ATTR_TRUSTED_DATA_KEY:
                case TAP_ATTR_TRUSTED_DATA_VALUE:
                case TAP_ATTR_TEST_REPORT:
                case TAP_ATTR_TEST_REQUEST_DATA:
                case TAP_ATTR_GET_MODULE_CREDENTIALS:
                case TAP_ATTR_CREATE_KEY_ENTROPY:
                    pTapBuffer = (TAP_Buffer *)pList->pAttributeList[i].pStructOfType;
                    DIGI_FREE((void **)&pTapBuffer->pBuffer);
                    break;

                case TAP_ATTR_TRUSTED_DATA_INFO:
                    /* Needs special handling */
                    break;

                case TAP_ATTR_CREDENTIAL_USAGE:
                    status = TAP_UTILS_clearEntityCredentialList((TAP_EntityCredentialList*)pList->pAttributeList[i].pStructOfType);
                    break;

                case TAP_ATTR_CREDENTIAL_SET:
                    status = TAP_UTILS_clearCredentialList((TAP_CredentialList*)pList->pAttributeList[i].pStructOfType);
                    break;

                case TAP_ATTR_ENTITY_CREDENTIAL:
                    pEntityCredential = (TAP_EntityCredential*)pList->pAttributeList[i].pStructOfType;
                    status = TAP_UTILS_clearCredentialList((TAP_CredentialList*)&(pEntityCredential->credentialList));
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to free memory for TAP_CredentialList %d. status %d = %s\n", __FUNCTION__,
                                __LINE__, i, status, MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    status = DIGI_FREE((void **)&(pEntityCredential));
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to free memory for TAP_EntityCredentials %d. status %d = %s\n", __FUNCTION__,
                                __LINE__, i, status, MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    break;

                case TAP_ATTR_PUBLIC_KEY:
                    status = TAP_UTILS_freePublicKey((TAP_PublicKey**)&(pList->pAttributeList[i].pStructOfType));
                    break;

                case TAP_ATTR_CREDENTIAL:
                    status = TAP_UTILS_clearCredential((TAP_Credential *)pList->pAttributeList[i].pStructOfType);
                    break;

                default:
                    break;
            }
            status = DIGI_FREE((void **)&(pList->pAttributeList[i].pStructOfType));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to free memory for attribute. status %d = %s\n", __FUNCTION__,
                       __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
            status = DIGI_MEMSET((ubyte *)&(pList->pAttributeList[i]), 0, sizeof(TAP_Attribute));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to memset memory for attribute list. status %d = %s\n", __FUNCTION__,
                       __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
    }
    status = DIGI_FREE((void **)&(pList->pAttributeList));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free memory for attribute list. status %d = %s\n", __FUNCTION__,
               __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pList->listLen = 0;

exit:

    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TAP_UTILS_copyModuleCapPropertyList(
        TAP_ModuleCapPropertyList *pDestPropList,
        TAP_ModuleCapPropertyList *pSrcPropList
)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    if ((NULL == pDestPropList) || (NULL == pSrcPropList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDestPropList->numProperties = 0;
    pDestPropList->pPropertyList = NULL;

    if ((0 == pSrcPropList->numProperties) || 
            (NULL == pSrcPropList->pPropertyList))
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(pDestPropList->pPropertyList),
                         pSrcPropList->numProperties, 
                         sizeof(*(pDestPropList->pPropertyList)));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for property list, "
                "status %d = %s\n", __FUNCTION__,
               __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pDestPropList->numProperties = pSrcPropList->numProperties;

    for (i = 0; i < pDestPropList->numProperties; i++)
    {
        pDestPropList->pPropertyList[i].propertyId = 
            pSrcPropList->pPropertyList[i].propertyId;

        if (0 != pSrcPropList->pPropertyList[i].propertyValue.bufferLen)
        {
            status = TAP_UTILS_copyBuffer(
                &(pDestPropList->pPropertyList[i].propertyValue),
                &(pSrcPropList->pPropertyList[i].propertyValue));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy memory for property-value, "
                    "status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        if (0 != pSrcPropList->pPropertyList[i].propertyDescription.bufferLen)
        {
            status = TAP_UTILS_copyBuffer(
                &(pDestPropList->pPropertyList[i].propertyDescription),
                &(pSrcPropList->pPropertyList[i].propertyDescription));

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy memory for property-description, "
                    "status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
    }

exit:
    if (OK != status)
    {
        TAP_UTILS_freeModuleCapPropertyList(pDestPropList);
    }
    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TAP_UTILS_freeModuleCapPropertyList(
        TAP_ModuleCapPropertyList *pList
)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    if (NULL == pList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Don't error on an empty list */
    if ((0 == pList->numProperties) && (NULL == pList->pPropertyList))
    {
        goto exit;
    }

    for (i = 0; i < pList->numProperties; i++)
    {
        status = TAP_UTILS_freeBuffer(
                    &(pList->pPropertyList[i].propertyValue));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free memory for %d-th property item "
                    "from property-list, status %d = %s\n", 
                    __FUNCTION__, __LINE__, i+1, status, 
                    MERROR_lookUpErrorCode(status));
            /* Do not exit, attempt to free other properties */
        }
        status = TAP_UTILS_freeBuffer(
                    &(pList->pPropertyList[i].propertyDescription));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free memory for %d-th property item "
                    "from property-list, status %d = %s\n", 
                    __FUNCTION__, __LINE__, i+1, status, 
                    MERROR_lookUpErrorCode(status));
            /* Do not exit, attempt to free other properties */
        }
    }

    status = DIGI_FREE((void **)&(pList->pPropertyList));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free memory for property-list, "
                "status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pList->numProperties = 0;

exit:
    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_getAttributeListLen(TAP_AttributeList *pList, ubyte4 *pListLen)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    ubyte4 j = 0;
    ubyte4 k = 0;
    TAP_EntityCredentialList *pEntityCredList = NULL;
    TAP_EntityCredential *pEntityCred = NULL;
    TAP_CredentialList *pCredList = NULL;
    TAP_Credential *pCred = NULL;

    if ((NULL == pList) || (NULL == pListLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pListLen = 0;

    if ((0 >= pList->listLen) || (NULL == pList->pAttributeList))
    {
        goto exit;
    }

    *pListLen +=  sizeof(ubyte4);
    *pListLen += (sizeof(TAP_ATTR_TYPE) + sizeof(ubyte4)) *  pList->listLen;
    for (i = 0; i < pList->listLen; i++)
    {
        if (NULL != pList->pAttributeList[i].pStructOfType)
        {
            *pListLen += pList->pAttributeList[i].length;

            /* Attributes which contain a variable length buffer must be taken into 
             * account separately */
            switch(pList->pAttributeList[i].type)
            {
                case TAP_ATTR_VENDOR_INFO:
                case TAP_ATTR_MODULE_KEY:
                case TAP_ATTR_RNG_SEED:
                case TAP_ATTR_RND_STIR:
                case TAP_ATTR_ENC_LABEL:
                case TAP_ATTR_BUFFER:
                case TAP_ATTR_TRUSTED_DATA_KEY:
                case TAP_ATTR_TRUSTED_DATA_VALUE:
                case TAP_ATTR_TEST_REPORT:
                case TAP_ATTR_TEST_REQUEST_DATA:
                case TAP_ATTR_ADDITIONAL_AUTH_DATA:
                case TAP_ATTR_OBJECT_VALUE:
                case TAP_ATTR_GET_MODULE_CREDENTIALS:
                case TAP_ATTR_OBJECT_ID_BYTESTRING:
                {
                    if (pList->pAttributeList[i].length != sizeof(TAP_Buffer))
                    {
                        status = ERR_INVALID_INPUT;
                        goto exit;
                    }

                    *pListLen += ((TAP_Buffer *)(pList->pAttributeList[i].pStructOfType))->bufferLen;
                }
                break;

                case TAP_ATTR_CREDENTIAL:
                {
                    if (pList->pAttributeList[i].length != sizeof(TAP_Credential))
                    {
                        status = ERR_INVALID_INPUT;
                        goto exit;
                    }

                    pCred = ((TAP_Credential *)(pList->pAttributeList[i].pStructOfType));

                    /* Account for the variable length credential buffer */
                    *pListLen += pCred->credentialData.bufferLen;
                }
                break;

                case TAP_ATTR_CREDENTIAL_SET:
                {
                    if (pList->pAttributeList[i].length != sizeof(TAP_CredentialList))
                    {
                        status = ERR_INVALID_INPUT;
                        goto exit;
                    }

                    pCredList = ((TAP_CredentialList *)(pList->pAttributeList[i].pStructOfType));

                    for(j = 0; j < pCredList->numCredentials; j++)
                    {
                        /* Account for the TAP_Credential */
                        *pListLen += sizeof(TAP_Credential);

                        /* Account for the variable length credential buffer */
                        *pListLen += pCredList->pCredentialList[j].credentialData.bufferLen;
                    }
                }
                break;

                case TAP_ATTR_ENTITY_CREDENTIAL:
                {
                    if (pList->pAttributeList[i].length != sizeof(TAP_EntityCredential))
                    {
                        status = ERR_INVALID_INPUT;
                        goto exit;
                    }

                    pEntityCred = ((TAP_EntityCredential *)(pList->pAttributeList[i].pStructOfType));

                    for(j = 0; j < pEntityCred->credentialList.numCredentials; j++)
                    {
                        /* Account for the TAP_Credential */
                        *pListLen += sizeof(TAP_Credential);

                        /* Account for the variable length credential buffer */
                        *pListLen += pEntityCred->credentialList.pCredentialList[j].credentialData.bufferLen;
                    }
                }
                break;

                case TAP_ATTR_CREDENTIAL_USAGE:
                {
                    if (pList->pAttributeList[i].length != sizeof(TAP_EntityCredentialList))
                    {
                        status = ERR_INVALID_INPUT;
                        goto exit;
                    }

                    pEntityCredList = ((TAP_EntityCredentialList *)(pList->pAttributeList[i].pStructOfType));

                    for(j = 0; j < pEntityCredList->numCredentials; j++)
                    {
                        pEntityCred = &pEntityCredList->pEntityCredentials[j];

                        /* Account for the size of the TAP_EntityCredential container */
                        *pListLen += sizeof(TAP_EntityCredential);

                        for(k = 0; k < pEntityCred->credentialList.numCredentials; k++)
                        {
                            /* Account for the TAP_Credential */
                            *pListLen += sizeof(TAP_Credential);

                            /* Account for the variable length credential buffer */
                            *pListLen += pEntityCred->credentialList.pCredentialList[k].credentialData.bufferLen;
                        }
                    }
                }
                break;

                case TAP_ATTR_SERIALIZED_OBJECT_BLOB:
                {
                    DB_PRINT("%s.%d Invalid serialized blob attribute in TAP_Key\n", 
                        __FUNCTION__, __LINE__);
                    status = ERR_TAP_UNSUPPORTED;
                    goto exit;

                }
                break;

                /* Public key data is already inside a TAP key at a different location, and
                 * will be serialized out. Do not try to serialize it twice. */
                case TAP_ATTR_PUBLIC_KEY:
                {
                    DB_PRINT("%s.%d Invalid public key attribute in TAP_Key\n", 
                        __FUNCTION__, __LINE__);
                    status = ERR_TAP_UNSUPPORTED;
                    goto exit;
                }
            }
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TAP_UTILS_joinCredentialList(
  TAP_CredentialList *pList1,
  TAP_CredentialList *pList2,
  TAP_CredentialList **ppOutList
  )
{
    MSTATUS status;
    ubyte4 i, n, elementCount;
    TAP_CredentialList *pNewList;
    TAP_Credential *pCreds = NULL;
    TAP_Credential *pCredA;
    TAP_Credential *pCredB;

    if (NULL == ppOutList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    *ppOutList = NULL;
    elementCount = 0;

    if (NULL != pList1)
        elementCount += pList1->numCredentials;
    
    if (NULL != pList2)
        elementCount += pList2->numCredentials;

    if (0 == elementCount)
    {
        status = OK;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pNewList, sizeof(*pNewList));
    if (OK != status)
        goto exit;
    
    pNewList->numCredentials = 0;

    status = DIGI_MALLOC((void **) &pCreds, elementCount*sizeof(*pCreds));
    if (OK != status)
        goto exit;

    if (NULL != pList1)
    {
        for (i = 0; i < pList1->numCredentials; i++)
        {
            n = pNewList->numCredentials;
            pCredA = &(pCreds[n]);
            pCredB = &(pList1->pCredentialList[i]);

            pCredA->credentialType = pCredB->credentialType;
            pCredA->credentialFormat = pCredB->credentialFormat;
            pCredA->credentialContext = pCredB->credentialContext;

            status = TAP_UTILS_copyBuffer (&(pCredA->credentialData), &(pCredB->credentialData));
            if (OK != status)
                goto exit;

            pNewList->numCredentials++;
        }
    }

    if (NULL != pList2)
    {
        for (i = 0; i < pList2->numCredentials; i++)
        {
            n = pNewList->numCredentials;
            pCredA = &(pCreds[n]);
            pCredB = &(pList2->pCredentialList[i]);

            pCredA->credentialType = pCredB->credentialType;
            pCredA->credentialFormat = pCredB->credentialFormat;
            pCredA->credentialContext = pCredB->credentialContext;

            status = TAP_UTILS_copyBuffer (&(pCredA->credentialData), &(pCredB->credentialData));
            if (OK != status)
                goto exit;

            pNewList->numCredentials++;
        }
    }

    pNewList->pCredentialList = pCreds;
    pCreds = NULL;
    *ppOutList = pNewList;
exit:
    if (NULL != pCreds)
        DIGI_FREE((void **)&pCreds);
    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_clearCredential(TAP_Credential *pCredential)
{
    MSTATUS status = OK;

    if (NULL == pCredential)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 != pCredential->credentialData.bufferLen) && (NULL != pCredential->credentialData.pBuffer))
    {
        status = shredMemory(&(pCredential->credentialData.pBuffer), pCredential->credentialData.bufferLen, TRUE);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free memory for credential. status %d = %s\n", __FUNCTION__,
                   __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/


MSTATUS TAP_UTILS_clearCredentialList(TAP_CredentialList *pCredentials)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    if (NULL == pCredentials)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pCredentials->pCredentialList)
    {
        /* Empty list - not really an error */
        goto exit;
    }

    for (i = 0; i < pCredentials->numCredentials; i++)
    {
        status = TAP_UTILS_clearCredential(&(pCredentials->pCredentialList[i]));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free memory for credential %d. status %d = %s\n", __FUNCTION__,
                   __LINE__, i, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    
    /* Free the list itself */
    status = DIGI_MEMSET_FREE((ubyte **)&pCredentials->pCredentialList, pCredentials->numCredentials * sizeof(TAP_Credential));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free memory for pCredentials->pCredentialList. status %d = %s\n", __FUNCTION__,
               __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_MEMSET((ubyte *)pCredentials, 0, sizeof(TAP_CredentialList));

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_clearEntityCredentialList(TAP_EntityCredentialList *pCredentials)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    if (NULL == pCredentials)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pCredentials->numCredentials) || (NULL == pCredentials->pEntityCredentials))
    {
        /* Empty list - not really an error */
        goto exit;
    }

    for (i = 0; i < pCredentials->numCredentials; i++)
    {
        status = TAP_UTILS_clearCredentialList(&(pCredentials->pEntityCredentials[i].credentialList));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free memory for TAP_CredentialList %d. status %d = %s\n", __FUNCTION__,
                   __LINE__, i, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = DIGI_FREE((void **)&(pCredentials->pEntityCredentials));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free memory for TAP_EntityCredentials %d. status %d = %s\n", __FUNCTION__,
               __LINE__, i, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_MEMSET((ubyte *)pCredentials, 0, sizeof(TAP_EntityCredentialList));

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyTapRSASignature(TAP_RSASignature *pDestSignature,
                                      TAP_RSASignature *pSrcSignature)
{
    MSTATUS status = OK;

    if ((NULL == pDestSignature) || (NULL == pSrcSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pSrcSignature->signatureLen) || (NULL == pSrcSignature->pSignature))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    pDestSignature->signatureLen = pSrcSignature->signatureLen;
    status = DIGI_CALLOC((void **)&(pDestSignature->pSignature), 1,
                         pDestSignature->signatureLen);
    if (OK != status)
    {
        goto exit;
    }
    status = DIGI_MEMCPY(pDestSignature->pSignature,
                        pSrcSignature->pSignature,
                        pDestSignature->signatureLen);

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyTapECCSignature(TAP_ECCSignature *pDestSignature,
                                      TAP_ECCSignature *pSrcSignature)
{
    MSTATUS status = OK;

    if ((NULL == pDestSignature) || (NULL == pSrcSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pSrcSignature->rDataLen) || (NULL == pSrcSignature->pRData)
     || (0 == pSrcSignature->sDataLen) || (NULL == pSrcSignature->pSData))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    pDestSignature->rDataLen = pSrcSignature->rDataLen;
    status = DIGI_CALLOC((void **)&(pDestSignature->pRData), 1,
                         pDestSignature->rDataLen);
    if (OK != status)
    {
        goto exit;
    }
    status = DIGI_MEMCPY(pDestSignature->pRData,
                        pSrcSignature->pRData,
                        pDestSignature->rDataLen);
    if (OK != status)
    {
        goto exit;
    }


    pDestSignature->sDataLen = pSrcSignature->sDataLen;
    status = DIGI_CALLOC((void **)&(pDestSignature->pSData), 1,
                         pDestSignature->sDataLen);
    if (OK != status)
    {
        goto exit;
    }
    status = DIGI_MEMCPY(pDestSignature->pSData,
                        pSrcSignature->pSData,
                        pDestSignature->sDataLen);

exit:

    return status;
}
/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyTapDSASignature(TAP_DSASignature *pDestSignature,
                                      TAP_DSASignature *pSrcSignature)
{
    MSTATUS status = OK;

    if ((NULL == pDestSignature) || (NULL == pSrcSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pSrcSignature->rDataLen) || (NULL == pSrcSignature->pRData)
     || (0 == pSrcSignature->sDataLen) || (NULL == pSrcSignature->pSData))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    pDestSignature->rDataLen = pSrcSignature->rDataLen;
    status = DIGI_CALLOC((void **)&(pDestSignature->pRData), 1,
                         pDestSignature->rDataLen);
    if (OK != status)
    {
        goto exit;
    }
    status = DIGI_MEMCPY(pDestSignature->pRData,
                         pSrcSignature->pRData,
                         pDestSignature->rDataLen);
    if (OK != status)
    {
        goto exit;
    }


    pDestSignature->rDataLen = pSrcSignature->sDataLen;
    status = DIGI_CALLOC((void **)&(pDestSignature->pSData), 1,
                         pDestSignature->sDataLen);
    if (OK != status)
    {
        goto exit;
    }
    status = DIGI_MEMCPY(pDestSignature->pSData,
                         pSrcSignature->pSData,
                         pDestSignature->sDataLen);

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyTapSymSignature(TAP_SymSignature *pDestSignature,
                                      TAP_SymSignature *pSrcSignature)
{
    MSTATUS status = OK;

    if ((NULL == pDestSignature) || (NULL == pSrcSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pSrcSignature->signatureLen) || (NULL == pSrcSignature->pSignature))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    pDestSignature->signatureLen = pSrcSignature->signatureLen;
    status = DIGI_CALLOC((void **)&(pDestSignature->pSignature), 1,
                         pDestSignature->signatureLen);
    if (OK != status)
    {
        goto exit;
    }
    status = DIGI_MEMCPY(pDestSignature->pSignature,
                         pSrcSignature->pSignature,
                         pDestSignature->signatureLen);

exit:

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
MSTATUS TAP_UTILS_copyTapMLDSASignature(TAP_MLDSASignature *pDestSignature,
                                      TAP_MLDSASignature *pSrcSignature)
{
    MSTATUS status = OK;

    if ((NULL == pDestSignature) || (NULL == pSrcSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pSrcSignature->signatureLen) || (NULL == pSrcSignature->pSignature))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    pDestSignature->signatureLen = pSrcSignature->signatureLen;
    status = DIGI_CALLOC((void **)&(pDestSignature->pSignature), 1,
                         pDestSignature->signatureLen);
    if (OK != status)
    {
        goto exit;
    }
    status = DIGI_MEMCPY(pDestSignature->pSignature,
                         pSrcSignature->pSignature,
                         pDestSignature->signatureLen);

exit:

    return status;
}
#endif

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyTapSignature(TAP_Signature *pDestSignature,
                                   TAP_Signature *pSrcSignature)
{
    MSTATUS status = OK;

    if ((NULL == pDestSignature) || (NULL == pSrcSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Copy non-algorithm-specific fields */
    pDestSignature->isDEREncoded = pSrcSignature->isDEREncoded;
    pDestSignature->keyAlgorithm = pSrcSignature->keyAlgorithm;

    if (TRUE == pSrcSignature->isDEREncoded)
    {
        if ((0 == pSrcSignature->derEncSignature.bufferLen) || (NULL == pSrcSignature->derEncSignature.pBuffer))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        pDestSignature->derEncSignature.bufferLen = pSrcSignature->derEncSignature.bufferLen;
        status = DIGI_CALLOC((void **)&(pDestSignature->derEncSignature.pBuffer), 1,
                             pDestSignature->derEncSignature.bufferLen);
        if (OK != status)
        {
            goto exit;
        }
        status = DIGI_MEMCPY(pDestSignature->derEncSignature.pBuffer,
                             pSrcSignature->derEncSignature.pBuffer,
                             pDestSignature->derEncSignature.bufferLen);
        if (OK != status)
        {
            goto exit;
        }
    }

    /* Copy algorithm-specific structure */
    switch(pSrcSignature->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            status = TAP_UTILS_copyTapRSASignature(&(pDestSignature->signature.rsaSignature), &(pSrcSignature->signature.rsaSignature));
            break;
        case TAP_KEY_ALGORITHM_ECC:
            status = TAP_UTILS_copyTapECCSignature(&(pDestSignature->signature.eccSignature), &(pSrcSignature->signature.eccSignature));
            break;
        case TAP_KEY_ALGORITHM_DSA:
            status = TAP_UTILS_copyTapDSASignature(&(pDestSignature->signature.dsaSignature), &(pSrcSignature->signature.dsaSignature));
            break;
        case TAP_KEY_ALGORITHM_AES:
            status = TAP_UTILS_copyTapSymSignature(&(pDestSignature->signature.aesSignature), &(pSrcSignature->signature.aesSignature));
            break;
        case TAP_KEY_ALGORITHM_HMAC:
            status = TAP_UTILS_copyTapSymSignature(&(pDestSignature->signature.hmacSignature), &(pSrcSignature->signature.hmacSignature));
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case TAP_KEY_ALGORITHM_MLDSA:
            status = TAP_UTILS_copyTapMLDSASignature(&(pDestSignature->signature.mldsaSignature), &(pSrcSignature->signature.mldsaSignature));
            break;
#endif
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            break;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeTapRSASignatureFields(TAP_RSASignature *pSignature)
{
    MSTATUS status = OK;

    if ((NULL == pSignature) || (NULL == pSignature->pSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_FREE((void **)(&(pSignature->pSignature)));
    pSignature->signatureLen = 0;

exit:

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
MSTATUS TAP_UTILS_freeTapMLDSASignatureFields(TAP_MLDSASignature *pSignature)
{
    MSTATUS status = OK;

    if (NULL == pSignature)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pSignature->pSignature)
    {
        status = DIGI_FREE((void **)(&(pSignature->pSignature)));
    }
    pSignature->signatureLen = 0;

exit:

    return status;
}
#endif

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeTapECCSignatureFields(TAP_ECCSignature *pSignature)
{
    MSTATUS status = OK;
    MSTATUS tmpStatus = OK;

    if (NULL == pSignature)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pSignature->pRData)
    {
        tmpStatus = DIGI_FREE((void **)(&(pSignature->pRData)));
        pSignature->rDataLen = 0;
    }

    if (NULL != pSignature->pSData)
    {
        status = DIGI_FREE((void **)(&(pSignature->pSData)));
        pSignature->sDataLen = 0;
    }

    if (OK == status)
        status = tmpStatus;

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeTapDSASignatureFields(TAP_DSASignature *pSignature)
{
    MSTATUS status = OK;
    MSTATUS tmpStatus = OK;

    if ((NULL == pSignature) || (NULL == pSignature->pRData) || (NULL == pSignature->pSData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    tmpStatus = DIGI_FREE((void **)(&(pSignature->pRData)));
    pSignature->rDataLen = 0;

    status = DIGI_FREE((void **)(&(pSignature->pSData)));
    pSignature->sDataLen = 0;

    if (OK == status)
        status = tmpStatus;

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeTapSymSignatureFields(TAP_SymSignature *pSignature)
{
    MSTATUS status = OK;

    if ((NULL == pSignature) || (NULL == pSignature->pSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_FREE((void **)(&(pSignature->pSignature)));
    pSignature->signatureLen = 0;

exit:

    return status;
}

/*------------------------------------------------------------------*/


MSTATUS TAP_UTILS_freeTapSignatureFields(TAP_Signature *pSignature)
{
    MSTATUS status = OK;

    if (NULL == pSignature)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pSignature->derEncSignature.pBuffer)
    {
        DIGI_FREE((void **)&pSignature->derEncSignature.pBuffer);
        pSignature->derEncSignature.bufferLen = 0;
    }

    switch (pSignature->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            status = TAP_UTILS_freeTapRSASignatureFields(&(pSignature->signature.rsaSignature));
            break;
        case TAP_KEY_ALGORITHM_ECC:
            status = TAP_UTILS_freeTapECCSignatureFields(&(pSignature->signature.eccSignature));
            break;
        case TAP_KEY_ALGORITHM_DSA:
            status = TAP_UTILS_freeTapDSASignatureFields(&(pSignature->signature.dsaSignature));
            break;
        case TAP_KEY_ALGORITHM_AES:
            status = TAP_UTILS_freeTapSymSignatureFields(&(pSignature->signature.aesSignature));
            break;
        case TAP_KEY_ALGORITHM_HMAC:
            status = TAP_UTILS_freeTapSymSignatureFields(&(pSignature->signature.hmacSignature));
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case TAP_KEY_ALGORITHM_MLDSA:
            status = TAP_UTILS_freeTapMLDSASignatureFields(&(pSignature->signature.mldsaSignature));
            break;
#endif
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            goto exit;
            break;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/


MSTATUS TAP_UTILS_freeTapSignature(TAP_Signature **ppSignature)
{
    MSTATUS status = OK;

    if ((NULL == ppSignature) || (NULL == *ppSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TAP_UTILS_freeTapSignatureFields(*ppSignature);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_FREE((void **)ppSignature);

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freePublicKey(TAP_PublicKey **ppPublicKey)
{
    MSTATUS status = OK;

    if ((NULL == ppPublicKey) || (NULL == *ppPublicKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TAP_UTILS_freePublicKeyFields(*ppPublicKey);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free public key fields. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

    status = DIGI_FREE((void **)ppPublicKey);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free public key. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freePublicKeyFields(TAP_PublicKey *pPublicKey)
{
    MSTATUS status = OK;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (pPublicKey->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            status = TAP_UTILS_freeRSAPublicKeyFields(&(pPublicKey->publicKey.rsaKey));
            break;
        case TAP_KEY_ALGORITHM_ECC:
            status = TAP_UTILS_freeECCPublicKeyFields(&(pPublicKey->publicKey.eccKey));
            break;
        case TAP_KEY_ALGORITHM_DSA:
            status = TAP_UTILS_freeDSAPublicKeyFields(&(pPublicKey->publicKey.dsaKey));
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case TAP_KEY_ALGORITHM_MLDSA:
            status = TAP_UTILS_freeMLDSAPublicKeyFields(&(pPublicKey->publicKey.mldsaKey));
            break;
#endif
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            break;
    }
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free algorithm-specific public key. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

    pPublicKey->keyAlgorithm = 0;

exit:

    return status;
}

/*------------------------------------------------------------------*/


MSTATUS TAP_UTILS_freeRSAPublicKeyFields(TAP_RSAPublicKey *pPublicKey)
{
    MSTATUS status = OK;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pPublicKey->pModulus)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pModulus), pPublicKey->modulusLen, TRUE);
        pPublicKey->modulusLen = 0;
    }

    if (NULL != pPublicKey->pExponent)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pExponent), pPublicKey->exponentLen, TRUE);
        pPublicKey->exponentLen = 0;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/


#ifdef __ENABLE_DIGICERT_PQC__
MSTATUS TAP_UTILS_freeMLDSAPublicKeyFields(TAP_MLDSAPublicKey *pPublicKey)
{
    MSTATUS status = OK;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pPublicKey->pPublicKey)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pPublicKey), pPublicKey->publicKeyLen, TRUE);
        pPublicKey->publicKeyLen = 0;
    }

exit:

    return status;
}
#endif

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeECCPublicKeyFields(TAP_ECCPublicKey *pPublicKey)
{
    MSTATUS status = OK;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pPublicKey->pPubX)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pPubX), pPublicKey->pubXLen, TRUE);
        pPublicKey->pubXLen = 0;
    }

    if (NULL != pPublicKey->pPubY)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pPubY), pPublicKey->pubYLen, TRUE);
        pPublicKey->pubYLen = 0;
    }

    pPublicKey->curveId = 0;

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_freeDSAPublicKeyFields(TAP_DSAPublicKey *pPublicKey)
{
    MSTATUS status = OK;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pPublicKey->pPrime)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pPrime), pPublicKey->primeLen, TRUE);
        pPublicKey->primeLen = 0;
    }

    if (NULL != pPublicKey->pSubprime)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pSubprime), pPublicKey->subprimeLen, TRUE);
        pPublicKey->subprimeLen = 0;
    }

    if (NULL != pPublicKey->pBase)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pBase), pPublicKey->baseLen, TRUE);
        pPublicKey->baseLen = 0;
    }

    if (NULL != pPublicKey->pPubVal)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pPubVal), pPublicKey->pubValLen, TRUE);
        pPublicKey->pubValLen = 0;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyPublicKey(TAP_PublicKey *pDestKey,
                                TAP_PublicKey *pSrcKey)
{
    MSTATUS status = OK;

    if ((NULL == pDestKey) || (NULL == pSrcKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (pSrcKey->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            status = TAP_UTILS_copyRSAPublicKey(&(pDestKey->publicKey.rsaKey), &(pSrcKey->publicKey.rsaKey));
            break;
        case TAP_KEY_ALGORITHM_ECC:
            status = TAP_UTILS_copyECCPublicKey(&(pDestKey->publicKey.eccKey), &(pSrcKey->publicKey.eccKey));
            break;
        case TAP_KEY_ALGORITHM_DSA:
            status = TAP_UTILS_copyDSAPublicKey(&(pDestKey->publicKey.dsaKey), &(pSrcKey->publicKey.dsaKey));
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case TAP_KEY_ALGORITHM_MLDSA:
            status = TAP_UTILS_copyMLDSAPublicKey(&(pDestKey->publicKey.mldsaKey), &(pSrcKey->publicKey.mldsaKey));
            break;
#endif
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            break;
    }

    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy algorithm-specific public key. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pDestKey->keyAlgorithm = pSrcKey->keyAlgorithm;


exit:

    return status;
}

/*------------------------------------------------------------------*/


MSTATUS TAP_UTILS_copyRSAPublicKey(TAP_RSAPublicKey *pDestKey,
                                   TAP_RSAPublicKey *pSrcKey)
{
    MSTATUS status = OK;

    if ((NULL == pDestKey) || (NULL == pSrcKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pSrcKey->modulusLen) || (NULL == pSrcKey->pModulus)
     || (0 == pSrcKey->exponentLen) || (NULL == pSrcKey->pExponent))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* copy modulus */
    pDestKey->modulusLen = pSrcKey->modulusLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pModulus), 1, pDestKey->modulusLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pModulus, pSrcKey->pModulus, pDestKey->modulusLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy modulus. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy exponent */
    pDestKey->exponentLen = pSrcKey->exponentLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pExponent), 1, pDestKey->exponentLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pExponent, pSrcKey->pExponent, pDestKey->exponentLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy exponent. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy schemes */
    pDestKey->encScheme = pSrcKey->encScheme;
    pDestKey->sigScheme = pSrcKey->sigScheme;


exit:

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
MSTATUS TAP_UTILS_copyMLDSAPublicKey(TAP_MLDSAPublicKey *pDestKey,
                                   TAP_MLDSAPublicKey *pSrcKey)
{
    MSTATUS status = OK;

    if ((NULL == pDestKey) || (NULL == pSrcKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pSrcKey->publicKeyLen) || (NULL == pSrcKey->pPublicKey))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* copy publicKey */
    pDestKey->publicKeyLen = pSrcKey->publicKeyLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pPublicKey), 1, pDestKey->publicKeyLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pPublicKey, pSrcKey->pPublicKey, pDestKey->publicKeyLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy public key. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy signature schemes */
    pDestKey->sigScheme = pSrcKey->sigScheme;

    /* Copy MLDSA cid */
    pDestKey->qsAlg = pSrcKey->qsAlg;

exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyECCPublicKey(TAP_ECCPublicKey *pDestKey,
                                   TAP_ECCPublicKey *pSrcKey)
{
    MSTATUS status = OK;

    if ((NULL == pDestKey) || (NULL == pSrcKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pSrcKey->pubXLen) || (NULL == pSrcKey->pPubX)
     || (0 == pSrcKey->pubYLen) || (NULL == pSrcKey->pPubY))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* copy curve */
    pDestKey->curveId = pSrcKey->curveId;

    /* copy pPubX */
    pDestKey->pubXLen = pSrcKey->pubXLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pPubX), 1, pDestKey->pubXLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pPubX, pSrcKey->pPubX, pDestKey->pubXLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pPubX. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy pPubY */
    pDestKey->pubYLen = pSrcKey->pubYLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pPubY), 1, pDestKey->pubYLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pPubY, pSrcKey->pPubY, pDestKey->pubYLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pPubY. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy schemes */
    pDestKey->encScheme = pSrcKey->encScheme;
    pDestKey->sigScheme = pSrcKey->sigScheme;


exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_copyDSAPublicKey(TAP_DSAPublicKey *pDestKey,
                                   TAP_DSAPublicKey *pSrcKey)
{
    MSTATUS status = OK;

    if ((NULL == pDestKey) || (NULL == pSrcKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pSrcKey->primeLen) || (NULL == pSrcKey->pPrime)
     || (0 == pSrcKey->subprimeLen) || (NULL == pSrcKey->pSubprime)
     || (0 == pSrcKey->pubValLen) || (NULL == pSrcKey->pPubVal)
     || (0 == pSrcKey->baseLen) || (NULL == pSrcKey->pBase))
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* copy prime */
    pDestKey->primeLen = pSrcKey->primeLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pPrime), 1, pDestKey->primeLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pPrime, pSrcKey->pPrime, pDestKey->primeLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pPrime. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy subprime */
    pDestKey->subprimeLen = pSrcKey->subprimeLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pSubprime), 1, pDestKey->subprimeLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pSubprime, pSrcKey->pSubprime, pDestKey->subprimeLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pSubprime. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy base */
    pDestKey->baseLen = pSrcKey->baseLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pBase), 1, pDestKey->baseLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pBase, pSrcKey->pBase, pDestKey->baseLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pBase. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy pubVal */
    pDestKey->pubValLen = pSrcKey->pubValLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pPubVal), 1, pDestKey->pubValLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pPubVal, pSrcKey->pPubVal, pDestKey->pubValLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pPubVal. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }


exit:

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_getPublicKeySize(const TAP_PublicKey *pPublicKey,
                                   ubyte4 *pKeySize)
{
    MSTATUS status = OK;
    ubyte4 serializedSize = 0;

    if ((NULL == pPublicKey) || (NULL == pKeySize))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pKeySize = 0;

    /* Get size of public key data */
    serializedSize = sizeof(pPublicKey->keyAlgorithm);

    switch (pPublicKey->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            serializedSize += sizeof(TAP_RSAPublicKey)
                           + pPublicKey->publicKey.rsaKey.modulusLen
                           + pPublicKey->publicKey.rsaKey.exponentLen;
            break;
        case TAP_KEY_ALGORITHM_ECC:
            serializedSize += sizeof(TAP_ECCPublicKey)
                           + pPublicKey->publicKey.eccKey.pubXLen
                           + pPublicKey->publicKey.eccKey.pubYLen;
            break;
        case TAP_KEY_ALGORITHM_DSA:
            serializedSize += sizeof(TAP_DSAPublicKey)
                           + pPublicKey->publicKey.dsaKey.primeLen
                           + pPublicKey->publicKey.dsaKey.subprimeLen
                           + pPublicKey->publicKey.dsaKey.baseLen
                           + pPublicKey->publicKey.dsaKey.pubValLen;
            break;
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            break;
    }
    if (OK != status)
    {
        goto exit;
    }

    *pKeySize = serializedSize;

exit:

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_UTILS_getKeySize(const TAP_Key *pKey, ubyte4 *pKeySize)
{
    MSTATUS status = OK;
    ubyte4 serializedSize = 0;
    ubyte4 tempSize = 0;

    if ((NULL == pKey) || (NULL == pKeySize))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pKeySize = 0;

    /* Get the TAP_ObjectData size */
    if (0 < pKey->providerObjectData.objectInfo.objectAttributes.listLen)
    {
        status = TAP_UTILS_getAttributeListLen((TAP_AttributeList *)&(pKey->providerObjectData.objectInfo.objectAttributes), &tempSize);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get size of objectAttributes. status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    serializedSize += sizeof(TAP_PROVIDER)
                   +  sizeof(TAP_ModuleId)
                   +  (2 * sizeof(TAP_EntityId))
                   + tempSize
                   + sizeof(TAP_BLOB_FORMAT)
                   + sizeof(TAP_BLOB_ENCODING)
                   + sizeof(ubyte4)
                   + pKey->providerObjectData.objectBlob.blob.bufferLen;

    /* Get the TAP_KeyData size */
    tempSize = 0;

    /* Get the public key size for asymmetric keys only */
    switch (pKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
        case TAP_KEY_ALGORITHM_DSA:
            status = TAP_UTILS_getPublicKeySize((const TAP_PublicKey *)&(pKey->keyData.publicKey), &tempSize);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to get size of publicKey. status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;
        default:
            tempSize = sizeof(TAP_KEY_ALGORITHM) + 1;
            break;
    }

    serializedSize += sizeof(TAP_KEY_ALGORITHM)
                   +  sizeof(TAP_KEY_USAGE)
                   + tempSize;

    /* Get the size of the algorithm specific KeyInfo structure */
    switch (pKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            /* Size of pTapKey.keyData.algKeyInfo.rsaInfo */
            serializedSize += sizeof(TAP_KeyInfo_RSA);
            break;
        case TAP_KEY_ALGORITHM_ECC:
            /* Size of pTapKey.keyData.algKeyInfo.eccInfo */
            serializedSize += sizeof(TAP_KeyInfo_ECC);
            break;
        case TAP_KEY_ALGORITHM_DSA:
            /* Size of pTapKey.keyData.algKeyInfo.dsaInfo */
            break;
        case TAP_KEY_ALGORITHM_AES:
            /* Size of pTapKey.keyData.algKeyInfo.aesInfo */
            serializedSize += sizeof(TAP_KeyInfo_AES);
            break;
        case TAP_KEY_ALGORITHM_DES:
            /* Size of pTapKey.keyData.algKeyInfo.desInfo */
            serializedSize += sizeof(TAP_KeyInfo_DES);
            break;    
        case TAP_KEY_ALGORITHM_TDES:
            /* Size of pTapKey.keyData.algKeyInfo.tdesInfo */
            serializedSize += sizeof(TAP_KeyInfo_TDES);
            break;
        case TAP_KEY_ALGORITHM_HMAC:
            /* Size of pTapKey.keyData.algKeyInfo.hmacInfo */
            serializedSize += sizeof(TAP_KeyInfo_HMAC);
            break;
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            break;
    }
    if (OK != status)
    {
        goto exit;
    }

    *pKeySize = serializedSize;

exit:

    return status;
}

/*------------------------------------------------------------------*/

char *TAP_UTILS_getProviderName(TAP_PROVIDER provider)
{
    char *pProviderName = NULL;

    if (TAP_PROVIDER_MAX < provider)
    {
        goto exit;
    }
    pProviderName = pTapProviderNames[provider];

exit:

    return pProviderName;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_readConfigFile(const char *pConfigFileName, TAP_Buffer *pConfigBuffer,
        byteBoolean useSpecifiedConfigFile)
{
    MSTATUS status = OK;
    int len = 0;

    status = DIGICERT_readFile(pConfigFileName, &pConfigBuffer->pBuffer,
                             &pConfigBuffer->bufferLen);

    if (OK != status)
    {
        /* if useSpecifiedConfigFile is TRUE, don't try any other file */
        if (useSpecifiedConfigFile)
        {
            DB_PRINT("%s.%d Error opening file %s, status %d = %s\n", __FUNCTION__, __LINE__, pConfigFileName, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
        else
        {
            /* Try local directory */
            /* Reverse search name for '/' character */
            len = DIGI_STRLEN((const sbyte *)pConfigFileName);

            if (len)
            {
                /* Using len as index */
                while((0 < len))
                {
#ifndef __RTOS_WIN32__
                    if ('/' == pConfigFileName[len])
#else
                    if (('/' == pConfigFileName[len]) ||
                            ('\\' == pConfigFileName[len]))
#endif
                    {
                        len++;
                        break;
                    }

                    len--;
                }

                status = DIGICERT_readFile(&pConfigFileName[len], 
                        &pConfigBuffer->pBuffer,
                       &pConfigBuffer->bufferLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error opening file %s, status %d = %s\n", 
                            __FUNCTION__, __LINE__, &pConfigFileName[len], status,
                            MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }
            else
            {
                DB_PRINT("%s.%d Error invalid file %s, status %d = %s\n", 
                        __FUNCTION__, __LINE__, pConfigFileName, status,
                        MERROR_lookUpErrorCode(status));
                status = ERR_INVALID_ARG;
            }
        }
    }

exit:
    return status;
}

#ifndef __ENABLE_TAP_REMOTE__
MSTATUS TAP_parseModuleCredentials(ubyte *pEncodedCredentials,
        ubyte4 encodedCredentialsLength, TAP_EntityCredentialList **ppEntityCredentialList,
        TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    ubyte *pDecodedBuffer = NULL;
    ubyte4 decodedBufferLen = 0;

    if ((NULL == pEncodedCredentials) || (0 == encodedCredentialsLength))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid input, pEncodedCredentials = %p, "
                "encodedCredentialsLength = %d\n", __FUNCTION__, __LINE__,
                pEncodedCredentials, (int)encodedCredentialsLength);

        goto exit;
    }

    /* Convert from Base64 encoded buffer */
    status = BASE64_decodeMessage(pEncodedCredentials, encodedCredentialsLength,
            &pDecodedBuffer, &decodedBufferLen);

    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to decode credentials file, status %d = %s\n", __FUNCTION__,
                __LINE__, (int)status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Get credentials list */
    status = MocTap_GetCredentialData((sbyte*)pDecodedBuffer, 
            decodedBufferLen, ppEntityCredentialList);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to read credentials from file, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    if (pDecodedBuffer)
        DIGI_FREE((void **)&pDecodedBuffer);

    return status;
}
#endif

/*------------------------------------------------------------------*/
MSTATUS TAP_UTILS_getServerInfo(char *pServerName, ubyte4 serverNameLen, ubyte4 *pServerNameLen, byteBoolean *pServerNameSpecified, ubyte4 *pServerPort)
{
    MSTATUS status = OK;

    if ((NULL == pServerName) || (NULL == pServerNameLen) ||
        (NULL == pServerNameSpecified) || (NULL == pServerPort))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!*pServerNameSpecified)
    {
        sbyte *pEnv = NULL;

        /* Server name */
        status = FMGMT_getEnvironmentVariableValueAlloc ((const sbyte *) "MOCANA_TAPSERVERNAME", &pEnv);
        if (OK == status)
        {
            *pServerNameLen = DIGI_STRLEN((const sbyte *)pEnv);
            if (*pServerNameLen > serverNameLen)
                *pServerNameLen = serverNameLen - 1;

            DIGI_MEMCPY(pServerName, pEnv, *pServerNameLen);
            pServerName[*pServerNameLen] = 0;
            (*pServerNameLen)++; /* Include the terminator */
            *pServerNameSpecified = 1;

            DIGI_FREE ((void **) &pEnv);
        }

        /* Server port */
        status = FMGMT_getEnvironmentVariableValueAlloc ((const sbyte *) "MOCANA_TAPSERVERPORT", &pEnv);
        if (OK == status)
        {
            *pServerPort = DIGI_ATOL((const sbyte *)pEnv, NULL);
            DIGI_FREE ((void **) &pEnv);
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__
/* Internal util method to set ECC public parametrs in AsymmetricKey structure */
static MSTATUS setEccKeyParams(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey,
                                const TAP_KeyInfo_ECC *pEccKeyInfo,
                                const TAP_ECCPublicKey *pEccKey)
{
    MSTATUS status = OK;
    TAP_Buffer  pointDataBuffer = {0};
    ubyte4 elementLen = 0;
    ubyte4 curveId = 0; /*curveId const as per crypto enum*/
    TAP_ECC_CURVE tapCurveId = TAP_ECC_CURVE_NONE;

    if (NULL == pAsymKey || NULL == pEccKey || NULL == pEccKeyInfo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (TAP_ECC_CURVE_NONE != pEccKeyInfo->curveId)
    {
        tapCurveId = pEccKeyInfo->curveId;
    }
    else if (TAP_ECC_CURVE_NONE != pEccKey->curveId)
    {
        tapCurveId = pEccKey->curveId;
    }
    else
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* Set point data buffer */
    switch(tapCurveId)
    {
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case TAP_ECC_CURVE_NIST_P192:
            elementLen = 24;
            curveId = cid_EC_P192;
            break;
#endif
        case TAP_ECC_CURVE_NIST_P224:
            elementLen = 28;
            curveId = cid_EC_P224;
            break;
        case TAP_ECC_CURVE_NIST_P256:
            elementLen = 32;
            curveId = cid_EC_P256;
            break;
        case TAP_ECC_CURVE_NIST_P384:
            elementLen = 48;
            curveId = cid_EC_P384;
            break;
        case TAP_ECC_CURVE_NIST_P521:
            elementLen = 66;
            curveId = cid_EC_P521;
            break;
        default:
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
    }

    /* +1 for header byte */
    pointDataBuffer.bufferLen = (2 * elementLen) + 1;
    /* We need to construct an ECC public key, which is a compression
        * byte followed by x and y, zero padded to exactly elementLen */
    status = DIGI_CALLOC((void **)&(pointDataBuffer.pBuffer),
                        sizeof(*(pointDataBuffer.pBuffer)),
                        pointDataBuffer.bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Error %d allocating ECC point buffer\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Indicate this is in the uncompressed form */
    pointDataBuffer.pBuffer[0] = 0x04;
    /* Copy in the x and y values */
    status = DIGI_MEMCPY(pointDataBuffer.pBuffer + 1,
                        pEccKey->pPubX, pEccKey->pubXLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Error %d copying ECC point buffer\n",
                         __FUNCTION__, __LINE__, status);
        goto exit;
    }
    status = DIGI_MEMCPY(pointDataBuffer.pBuffer + 1 + elementLen,
                        pEccKey->pPubY, pEccKey->pubYLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Error %d copying ECC point buffer\n",
                __FUNCTION__, __LINE__,  status);
        goto exit;
    }

    /* Set ECC parameters using curveId, point data.
     * Set Scalar values as NULL/0 */
    status = CRYPTO_setECCParameters(MOC_ECC(hwAccelCtx) pAsymKey, curveId,
                        pointDataBuffer.pBuffer, pointDataBuffer.bufferLen,
                        NULL, 0);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Error %d setting ECC parameters\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    /*TODO: Check if ECC key signature scheme needs to be set pEccKey->sigScheme*/

exit:
    if (NULL != pointDataBuffer.pBuffer)
    {
        status = TAP_UTILS_freeBuffer(&pointDataBuffer);
        if (OK != status)
            DB_PRINT("%s.%d: TAP_UTILS_freeBuffer failed, status=%d", __FUNCTION__, __LINE__, status);
    }

    return status;
}
#endif /*__ENABLE_DIGICERT_ECC__*/

#ifndef __ENABLE_TAP_MIN_SIZE__
/* Internal util method to set RSA public parameters to AsymmetricKey
 * structure */
static MSTATUS setRSAKeyParams(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey,
                                const TAP_RSAPublicKey *pRsaKey)
{
    MSTATUS status = OK;
    ubyte4 exponent = 0;

    if (NULL == pAsymKey || NULL == pRsaKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Get exponent value */
    if (pRsaKey->exponentLen < sizeof(exponent) ||
        NULL == pRsaKey->pExponent)
    {
        status = ERR_GENERAL;
        goto exit;
    }
    DIGI_MEMCPY(&exponent, pRsaKey->pExponent, sizeof(exponent));

    /* Init AsymKey with public parameters */
    status = CRYPTO_setRSAParameters(MOC_RSA(hwAccelCtx) pAsymKey, exponent,
                              pRsaKey->pModulus, pRsaKey->modulusLen,
                              NULL, 0, NULL, 0,
                              NULL);
    if (OK != status)
    {
        DB_PRINT("%s.%d: RSA setPublicKey failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

exit:
    return status;
}


MSTATUS TAP_UTILS_extractPublicKey(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pDestKey, TAP_Key *pSrcKey)
{
    MSTATUS status;

    if ( (NULL == pDestKey) || (NULL == pSrcKey) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (TAP_KEY_ALGORITHM_RSA == pSrcKey->keyData.keyAlgorithm)
    {
        status = setRSAKeyParams(MOC_RSA(hwAccelCtx) pDestKey, &(pSrcKey->keyData.publicKey.publicKey.rsaKey));
    }
    else
    {
        status = ERR_TAP_INVALID_ALGORITHM;
    }

    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy algorithm-specific public key to AsymmetricKey. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

exit:

    return status;
}
#endif

MSTATUS TAP_UTILS_getTapHashAlgFromHashId(
    ubyte hashId, TAP_HASH_ALG *pTapHashAlg)
{
    MSTATUS status;

    if (NULL == pTapHashAlg)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (hashId)
    {
        case ht_sha1:
            *pTapHashAlg = TAP_HASH_ALG_SHA1;
            break;
        case ht_sha256:
            *pTapHashAlg = TAP_HASH_ALG_SHA256;
            break;
        case ht_sha384:
            *pTapHashAlg = TAP_HASH_ALG_SHA384;
            break;
        case ht_sha512:
            *pTapHashAlg = TAP_HASH_ALG_SHA512;
            break;

        default:
            status = ERR_TAP_UNSUPPORTED_HASH_ID;
            goto exit;
    }

    status = OK;

exit:

    return status;
}

MSTATUS TAP_UTILS_getHashIdFromTapHashAlg(
    TAP_HASH_ALG tapHashAlg, ubyte *pHashId)
{
    MSTATUS status;

    if (NULL == pHashId)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (tapHashAlg)
    {
        case TAP_HASH_ALG_SHA1:
            *pHashId = ht_sha1;
            break;
        case TAP_HASH_ALG_SHA256:
            *pHashId = ht_sha256;
            break;
        case TAP_HASH_ALG_SHA384:
            *pHashId = ht_sha384;
            break;
        case TAP_HASH_ALG_SHA512:
            *pHashId = ht_sha512;
            break;

        default:
            status = ERR_TAP_UNSUPPORTED_HASH_ID;
            goto exit;
    }

    status = OK;

exit:

    return status;
}

/* Function to serialize TAP_PublicKey to PEM bytes
 */
#ifndef __ENABLE_TAP_MIN_SIZE__
MOC_EXTERN MSTATUS TAP_UTILS_serializePubKeyToPEM(const TAP_KeyData *pKeyData,
                                TAP_Buffer *pPemBuffer)
{
    MSTATUS status = OK;
    AsymmetricKey asymKey = {0};
    const TAP_RSAPublicKey *pRsaKey = NULL;
#ifdef __ENABLE_DIGICERT_ECC__
    const TAP_ECCPublicKey *pEccKey = NULL;
#endif
    const TAP_PublicKey *pPubKey = NULL;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    /* just in case build uses both TAP and hwAccel */
    hwAccelDescr hwAccelCtx = 0;
#endif
    
    if (NULL == pKeyData ||
        NULL == pPemBuffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif

    pPubKey = &(pKeyData->publicKey);

    if (OK > (status = CRYPTO_initAsymmetricKey(&asymKey)))
    {
        DB_PRINT("%s.%d: Error %d initializing Asymmetric key\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch (pPubKey->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        {
            pRsaKey = &(pPubKey->publicKey.rsaKey);
            if (NULL == pRsaKey)
            {
                status = ERR_GENERAL;
                goto exit;
            }
            /* Init assymetric key with RSA Key parameters */
            status = setRSAKeyParams(MOC_RSA(hwAccelCtx) &asymKey, pRsaKey);
            if (OK != status)
            {
                DB_PRINT("%s.%d: Failed setting RSA key parameters, "
                        "status = %d\n", __FUNCTION__, __LINE__, status);
                goto exit;
            }
        }
        break;
#ifdef __ENABLE_DIGICERT_ECC__
        case TAP_KEY_ALGORITHM_ECC:
        {
            pEccKey = &(pPubKey->publicKey.eccKey);
            if (NULL == pEccKey)
            {
                status = ERR_GENERAL;
                goto exit;
            }
            /* Init asymmetric-key with ECC key parameters */
            status = setEccKeyParams(MOC_ECC(hwAccelCtx) &asymKey,
                             &(pKeyData->algKeyInfo.eccInfo), pEccKey);
            if (OK != status)
            {
                DB_PRINT("%s.%d: Failed setting ECC key parameters, "
                        "status = %d\n", __FUNCTION__, __LINE__, status);
                goto exit;
            }
        }
        break;
#endif /*__ENABLE_DIGICERT_ECC__*/
        default:
            status = ERR_INVALID_ARG;
            break;
    }

    if (OK != status)
    {
        DB_PRINT("%s.%d: Failed setting key parameters, "
            "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }
    /* Serialize the in PEM Format */
    status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, publicKeyPem,
                                &(pPemBuffer->pBuffer),
                                &(pPemBuffer->bufferLen));
    if (OK != status)
    {
        DB_PRINT("%s.%d: Failed to serialize public-key, "
            "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

exit:
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return status;
}
#endif

/*------------------------------------------------------------------*/


#if defined(__RTOS_WIN32__) 

/*------------------------------------------------------------------*/
/*
* Function to retrieve Folder path for directory containing MOCANA files
* Caller should free memory allocated to ppMocAppPath usign DIGI_FREE
* This function does not check for physical existence of MOCANA app path.
* MOCANA app path "%PROGRAMDATA%\Mocana" is expected
* to be created as part of the deployment
* This function computes PATH of length lesser than MAX_FILE_PATH(256)
*/

static MSTATUS
getWinAppDataPath(ubyte **ppTapAppPath, ubyte4 *pTapAppPathLength)
{
    MSTATUS status = OK;
    HRESULT hr = S_OK;
    ubyte*  pAppPath = NULL;
    ubyte*  pAppMocDirName = NULL;
    ubyte*  pRetVal = NULL;

    if (NULL == ppTapAppPath || NULL == pTapAppPathLength)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC(&pAppPath, MAX_PATH, sizeof(ubyte));
    if (OK != status)
    {
        goto exit;
    }

    /* Call windows shell function to retrieve program data location.
    Using the SHGetFolderPathA() version instead of SHGetFolderPath(), as incoming buffer ppMocAppPath is of type ubyte* */
    hr = SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, pAppPath);
    if (!SUCCEEDED(hr))
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

    status = DIGI_CALLOC(ppTapAppPath, MAX_PATH, sizeof(ubyte));
    if (OK != status)
    {
        goto exit;
    }

    /* Combine path received from SHGetFolderPathA() with mocana directory */
    pRetVal = PathCombineA(*ppTapAppPath, pAppPath, MOCANA_APPDATA_DIR_NAME);

    if (NULL == pRetVal || NULL == *ppTapAppPath)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

    *pTapAppPathLength = DIGI_STRLEN(*ppTapAppPath);

exit:

    DIGI_FREE(&pAppPath);
    DIGI_FREE(&pAppMocDirName);

    return status;
}


/********************************************************************/
/*
* Function to retrieve absolute dir path of configuration files for windows.
* Configuration files are located inside '%ProgramData%\Mocana\',
* To retrieve a dir-path relateive to this location the pConfigDirName value
* has to be relative to this path,
*
* if pConfigDirName is empty then, the root Mocana dir is returned
* '%ProgramData%\Mocana\'
*
* Caller is responsible to free memory allocated to
* ppConfigFilePath using DIGI_FREE
*
* This function does NOT check for resulting file path's existence.
* This function computes PATH of length lesser than MAX_FILE_PATH(256)
*/

MOC_EXTERN MSTATUS
TAP_UTILS_getWinConfigDir(ubyte **ppConfigDirPath, const ubyte *pConfigDirName)
{
    MSTATUS status = OK;
    ubyte*  pNanotapAppPath = NULL;
    ubyte4  pathLength = 0;
    ubyte*  pRetVal  = NULL;

    if (NULL == ppConfigDirPath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = getWinAppDataPath(&pNanotapAppPath, &pathLength);
    if (OK != status && NULL != pNanotapAppPath)
    {
        goto exit;
    }

    status = DIGI_CALLOC(ppConfigDirPath, MAX_PATH, sizeof(ubyte));
    if (OK != status)
    {
        goto exit;
    }

    /* Combine path received from getWinAppDataPath with mocana directory */
    pRetVal = PathCombineA(*ppConfigDirPath,
                                  pNanotapAppPath, pConfigDirName);
    if (NULL == pRetVal || NULL == *ppConfigDirPath)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

    pRetVal = PathAddBackslashA(*ppConfigDirPath);
    if (NULL == pRetVal)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

exit:
    DIGI_FREE(&pNanotapAppPath);
    return status;
}

/********************************************************************/
/*
* Function to retrieve absolute file path of configuration files for windows.
* Configuration files are located inside "%ProgramData%\Mocana\",
* hence pConfigFileRelativePath value has to be relative to this path
* Caller is responsible to free memory allocated to
* ppConfigFilePath using DIGI_FREE
* This function does NOT check for resulting file path's existence.
* This function computes PATH of length lesser than MAX_FILE_PATH(256)
*/

MOC_EXTERN MSTATUS
TAP_UTILS_getWinConfigFilePath(ubyte **ppConfigFilePath,
    const ubyte *pConfigFileRelativePath)
{
    MSTATUS status = OK;
    ubyte*  pNanotapAppPath = NULL;
    ubyte4  pathLength = 0;

    if (NULL == ppConfigFilePath || NULL == pConfigFileRelativePath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = getWinAppDataPath(&pNanotapAppPath, &pathLength);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC(ppConfigFilePath, MAX_PATH, sizeof(ubyte));
    if (OK != status)
    {
        goto exit;
    }

    /* Combine path received from getWinAppDataPath with mocana directory */
    ubyte *pRetVal = PathCombineA(*ppConfigFilePath,
        pNanotapAppPath, pConfigFileRelativePath);

    if (NULL == pRetVal || NULL == *ppConfigFilePath)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

exit:

    DIGI_FREE(&pNanotapAppPath);

    return status;
}

#endif /* __RTOS_WIN32__ */

MOC_EXTERN MSTATUS TAP_UTILS_isPathRelative(const ubyte* pPathStr, const ubyte4 pathLen,
                                byteBoolean *pResult)
{
    MSTATUS status = OK;

    if (NULL == pPathStr || NULL == pResult)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (0 == pathLen)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

#ifdef __RTOS_WIN32__
    *pResult = (PathIsRelativeA(pPathStr)) ? TRUE : FALSE;
#else
    *pResult = ('/' == pPathStr[0]) ? FALSE : TRUE;
#endif

exit:
    return status;
}

#endif
