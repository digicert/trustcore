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

#include "moctap_tools_utils.h"

#if defined(__RTOS_WIN32__)
#define TPM2_CONFIGURATION_FILE "tpm2.conf"
#define TPM_CONF_FILE_PATH  "tpm12.conf"
#else
#include "../../common/tpm2_path.h"
#define TPM_CONF_FILE_PATH  "/etc/mocana/tpm12.conf"
#endif /* DIGICERT_TPM2_CONF_PATH */

MSTATUS freeTapProviderEntry(tapProviderEntry **ppTapProviderEntry)
{
    MSTATUS status = OK;
    tapProviderEntry *pTapProviderEntry = NULL;

    if (NULL == ppTapProviderEntry || NULL == *ppTapProviderEntry)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pTapProviderEntry = *ppTapProviderEntry;
    if (NULL != pTapProviderEntry->providerName)
    {
        status = DIGI_FREE((void **)&(pTapProviderEntry->providerName));
        if (OK != status)
            MOCTAP_DEBUG_PRINT_1("Failed to free memory of providerName");
    }

    if (NULL != pTapProviderEntry->configFilePath)
    {
        status = DIGI_FREE((void **)&(pTapProviderEntry->configFilePath));
        if (OK != status)
            MOCTAP_DEBUG_PRINT_1("Failed to free memory of configFilePath");
    }

    status = DIGI_FREE((void**)ppTapProviderEntry);
    if (OK != status)
        MOCTAP_DEBUG_PRINT_1("Failed to free memory of TapProviderEntry");
    *ppTapProviderEntry = NULL;
exit:
    return status;
}

static MSTATUS copyProviderEntry(tapProviderEntry *pSource,
                             tapProviderEntry *pDest)
{
    MSTATUS status = OK;
    char *pValue = NULL;
    ubyte4 valueLen = 0;

    if (NULL == pDest || NULL == pSource)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDest->providerType = pSource->providerType;

    if (NULL != pDest->providerName)
        DIGI_FREE((void **)pDest->providerName);
    if (NULL != pSource->providerName)
    {
        valueLen = DIGI_STRLEN(pSource->providerName);
        status = DIGI_CALLOC((void**)&(pDest->providerName),
                                 valueLen+1, sizeof(char));
        if (OK != status)
        {
            MOCTAP_DEBUG_PRINT("Failed allocating memory for provider name, "
                        "status = %d.", status);
            goto exit;
        }
        status = DIGI_MEMCPY(pDest->providerName,
                             pSource->providerName, valueLen);
        if (OK != status)
        {
            MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
            goto exit;
        }
    }

    if (NULL != pDest->configFilePath)
        DIGI_FREE((void **)pDest->configFilePath);
    if (NULL != pSource->configFilePath)
    {
        valueLen = DIGI_STRLEN(pSource->configFilePath);
        status = DIGI_CALLOC((void**)&(pDest->configFilePath),
                                 valueLen+1, sizeof(char));
        if (OK != status)
        {
            MOCTAP_DEBUG_PRINT("Failed allocating memory for provider name, "
                        "status = %d.", status);
            goto exit;
        }

        status = DIGI_MEMCPY(pDest->configFilePath,
                             pSource->configFilePath, valueLen);
        if (OK != status)
        {
            MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
            goto exit;
        }
    }

exit:
    return status;
}

MSTATUS getProviderFromName(const ubyte* providerName,
            tapProviderEntry** ppTapProviderEntry)
{
    MSTATUS status = OK;
    tapProviderEntry *pProvider = NULL;
    sbyte4 cmpResult = 1;

    tapProviderEntry tapProviders[] = {
        {"tpm12", TAP_PROVIDER_TPM, TPM_CONF_FILE_PATH},
        {"tpm2", TAP_PROVIDER_TPM2, TPM2_CONFIGURATION_FILE},
        NULL
    };


    if (NULL == providerName)
    {
        goto exit;
    }

    pProvider = tapProviders;
    while (NULL != pProvider)
    {
        status = DIGI_MEMCMP((const ubyte *)providerName,
                            (const ubyte *)pProvider->providerName,
                            DIGI_STRLEN((const sbyte *)pProvider->providerName),
                            &cmpResult);
        if (OK != status)
        {
            MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
            goto exit;
        }

        if (!cmpResult)
        {
            MOCTAP_DEBUG_PRINT("Found provider for provider name %s",
                               pProvider->providerName);
            break;
        }
        pProvider++;
    }

    if (NULL == pProvider)
    {
        status = ERR_GENERAL;
        goto exit;
    }

    status = DIGI_CALLOC((void**)ppTapProviderEntry, 1,
                         sizeof(**ppTapProviderEntry));
    if (OK != status)
    {
        MOCTAP_DEBUG_PRINT("Failed allocating memory for provider entry, "
                        "status = %d.", status);
        goto exit;
    }

    status = copyProviderEntry(pProvider, *ppTapProviderEntry);

exit:
    if (OK != status)
    {
        if (NULL != (void**)ppTapProviderEntry)
        {
            freeTapProviderEntry(ppTapProviderEntry);
        }
    }
    return status;
}

