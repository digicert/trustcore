
/*
 * sample_tapcreds.c
 *
 * @details  This file contains a sample credentials processing function
 *
 * Mocana Trust Anchor Platform APIs
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
#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#ifdef __ENABLE_DIGICERT_TAP__
#include "tap.h"
#include "tap_api.h"
#include "tap_utils.h"
#include "../smp/smp_tpm2/smp_tap_tpm2.h"

/*------------------------------------------------------------------*/

#define SOME_PWD_LEN    0
#define SOME_PWD        (ubyte *)NULL

#ifdef __DISABLE_DIGICERT_TAP_CREDS_FILE__
#define DEFAULT_SRK_PASSWORD_LEN         SOME_PWD_LEN
#define DEFAULT_SRK_PASSWORD             SOME_PWD
#define DEFAULT_EK_PASSWORD_LEN          SOME_PWD_LEN
#define DEFAULT_EK_PASSWORD              SOME_PWD
#define DEFAULT_LOCKOUT_PASSWORD_LEN     SOME_PWD_LEN
#define DEFAULT_LOCKOUT_PASSWORD         SOME_PWD
#define DEFAULT_ENDORSEMENT_PASSWORD_LEN SOME_PWD_LEN
#define DEFAULT_ENDORSEMENT_PASSWORD     SOME_PWD
#define DEFAULT_STORAGE_PASSWORD_LEN     SOME_PWD_LEN
#define DEFAULT_STORAGE_PASSWORD         SOME_PWD


MSTATUS allocateTPM2CredentialsList(TAP_EntityCredentialList **ppEntityCredentialList)
{
    MSTATUS status = OK;
    ubyte4 numCredentials = 5;
    ubyte4 i = 0;
    TAP_EntityCredentialList *pEntityCredList = NULL;

    if (NULL == ppEntityCredentialList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC((void **)ppEntityCredentialList, 1, sizeof(**ppEntityCredentialList));
    if (OK != status)
        goto exit;

    pEntityCredList = *ppEntityCredentialList;

    /* Allocate element structure */
    status = DIGI_CALLOC((void **) &(pEntityCredList->pEntityCredentials), numCredentials, sizeof(TAP_EntityCredential));

    if (OK != status)
    {
        goto exit;
    }
    i = 0;
    {
        status = DIGI_CALLOC((void **) &(pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList), 1,
                sizeof(TAP_Credential));
        if (OK != status)
        {
            goto exit;
        }
        pEntityCredList->pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_UNKNOWN;
        pEntityCredList->pEntityCredentials[i].parentId = 0;
        pEntityCredList->pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_TOKEN;
        pEntityCredList->pEntityCredentials[i].entityId = TAP_TPM2_RH_ENDORSEMENT_ID;

        pEntityCredList->pEntityCredentials[i].credentialList.numCredentials = 1;

        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[i].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[i].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[i].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
        //pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[i].credentialData.bufferLen = pOpts->newEhAuthValue.size;
        //pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[i].credentialData.pBuffer = pOpts->newEhAuthValue.buffer;
        i++;
    }

    {
        status = DIGI_CALLOC((void **) &(pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList), 1,
                sizeof(TAP_Credential));
        if (OK != status)
        {
            goto exit;
        }
        pEntityCredList->pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_UNKNOWN;
        pEntityCredList->pEntityCredentials[i].parentId = 0;
        pEntityCredList->pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_TOKEN;
        pEntityCredList->pEntityCredentials[i].entityId = TAP_TPM2_RH_OWNER_ID;

        pEntityCredList->pEntityCredentials[i].credentialList.numCredentials = 1;

        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
        //pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen = pOpts->newShAuthValue.size;
        //pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer = pOpts->newShAuthValue.buffer;
        i++;
    }

    {
        status = DIGI_CALLOC((void **) &(pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList), 1,
                sizeof(TAP_Credential));
        if (OK != status)
        {
            goto exit;
        }
        pEntityCredList->pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_UNKNOWN;
        pEntityCredList->pEntityCredentials[i].parentId = 0;
        pEntityCredList->pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_MODULE;
        pEntityCredList->pEntityCredentials[i].entityId = TAP_TPM2_RH_LOCKOUT_ID;

        pEntityCredList->pEntityCredentials[i].credentialList.numCredentials = 1;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
        //pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen = pOpts->newLhAuthValue.size;
        //pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer = pOpts->newLhAuthValue.buffer;
        i++;
    }
    {
        status = DIGI_CALLOC((void **) &(pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList), 1,
                sizeof(TAP_Credential));
        if (OK != status)
        {
            goto exit;
        }
        pEntityCredList->pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_TOKEN;
        pEntityCredList->pEntityCredentials[i].parentId = TAP_TPM2_RH_ENDORSEMENT_ID;
        pEntityCredList->pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_OBJECT;
        pEntityCredList->pEntityCredentials[i].entityId = TAP_TPM2_RH_EK_ID;

        pEntityCredList->pEntityCredentials[i].credentialList.numCredentials = 1;

        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
        //pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen = pOpts->ekAuthValue.size;
        //pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer = pOpts->ekAuthValue.buffer;
        i++;
    }
    {
        status = DIGI_CALLOC((void **) &(pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList), 1,
                sizeof(TAP_Credential));
        if (OK != status)
        {
            goto exit;
        }

        pEntityCredList->pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_TOKEN;
        pEntityCredList->pEntityCredentials[i].parentId = TAP_TPM2_RH_OWNER_ID;
        pEntityCredList->pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_OBJECT;
        pEntityCredList->pEntityCredentials[i].entityId = TAP_TPM2_RH_SRK_ID;

        pEntityCredList->pEntityCredentials[i].credentialList.numCredentials = 1;

        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
        //pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen = pOpts->srkAuthValue.size;
        //pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer = pOpts->srkAuthValue.buffer;
        i++;
    }

    pEntityCredList->numCredentials  = numCredentials;

exit:
    return status;
}

MSTATUS populateTPM2Credentials(TAP_EntityCredentialList *pEntityCredList)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    ubyte **ppBuffer = NULL;
    ubyte4 *pBufferLen = NULL;
    ubyte *pPwd = NULL;
    ubyte4 pwdLen = 0;

    if (NULL == pEntityCredList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i = 0; i < pEntityCredList->numCredentials; i++)
    {
        switch(pEntityCredList->pEntityCredentials[i].entityId)
        {
            case TAP_TPM2_RH_SRK_ID:
                pwdLen = DEFAULT_SRK_PASSWORD_LEN;
                pPwd = DEFAULT_SRK_PASSWORD;
                ppBuffer = &pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer;
                pBufferLen = &pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen;

                break;

            case TAP_TPM2_RH_EK_ID:
                pwdLen = DEFAULT_EK_PASSWORD_LEN;
                pPwd = DEFAULT_EK_PASSWORD;
                ppBuffer = &pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer;
                pBufferLen = &pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen;

                break;

            case TAP_TPM2_RH_LOCKOUT_ID:
                pwdLen = DEFAULT_LOCKOUT_PASSWORD_LEN;
                pPwd = DEFAULT_LOCKOUT_PASSWORD;
                ppBuffer = &pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer;
                pBufferLen = &pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen;

                break;

            case TAP_TPM2_RH_ENDORSEMENT_ID:
                pwdLen = DEFAULT_ENDORSEMENT_PASSWORD_LEN;
                pPwd = DEFAULT_ENDORSEMENT_PASSWORD;
                ppBuffer = &pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer;
                pBufferLen = &pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen;

                break;

            case TAP_TPM2_RH_OWNER_ID:
                pwdLen = DEFAULT_STORAGE_PASSWORD_LEN;
                pPwd = DEFAULT_STORAGE_PASSWORD;
                ppBuffer = &pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer;
                pBufferLen = &pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen;

                break;

            default:
                status = ERR_INVALID_ARG;
                goto exit;
                break;
        }

        if (pwdLen > 0)
        {
            status = DIGI_MALLOC((void **)ppBuffer, pwdLen);
            if (OK == status)
            {
                status = DIGI_MEMCPY(*ppBuffer, pPwd, pwdLen);
                if (OK == status)
                {
                    *pBufferLen = pwdLen;
                }
            }
            if (OK != status)
                goto exit;
        }
        else
        {
            pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen = pwdLen;
            pEntityCredList->pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer = pPwd;
        }

        ppBuffer = NULL;
        pBufferLen = NULL;
        pPwd = NULL;
        pwdLen = 0;
    }

exit:
    return status;
}

MSTATUS TAP_getModuleCredentials(TAP_Module *pModule, const char *pConfigFilePath,
    byteBoolean useSpecifiedConfigFilePath,
    TAP_EntityCredentialList **ppEntityCredentialList,
    TAP_ErrorContext *pErrContext)
{
    MOC_UNUSED(pModule);
    MOC_UNUSED(pConfigFilePath);
    MOC_UNUSED(useSpecifiedConfigFilePath);
    MOC_UNUSED(pErrContext);

    MSTATUS status = OK;

    /* check input */
    if ((NULL == ppEntityCredentialList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppEntityCredentialList = NULL;

    /* Allocate Credentials list for TPM2 */
    status = allocateTPM2CredentialsList(ppEntityCredentialList);

    /* Populate credentials */
    if (OK == status)
        status = populateTPM2Credentials(*ppEntityCredentialList);

exit:
    if (OK != status)
    {
        if (ppEntityCredentialList && *ppEntityCredentialList)
        {
            TAP_UTILS_clearEntityCredentialList(*ppEntityCredentialList);
            DIGI_FREE((void **)ppEntityCredentialList);
        }
    }

    return status;
}

/*------------------------------------------------------------------*/
#ifdef __ENABLE_TAP_REMOTE__
MSTATUS TAPS_getModuleCredentials(TAP_ConfigInfoList *pConfigInfoList,
        int moduleId,
        TAP_PROVIDER providerType, TAP_EntityCredentialList **ppServerCredentialsList)
{
    MOC_UNUSED(pConfigInfoList);
    MOC_UNUSED(moduleId);

    MSTATUS status = OK;

    if ((NULL == ppServerCredentialsList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppServerCredentialsList = NULL;

    switch (providerType)
    {
        case TAP_PROVIDER_TPM2:
            /* Allocate Credentials list for TPM2 */
            status = allocateTPM2CredentialsList(ppServerCredentialsList);

            /* Populate credentials */
            if (OK == status)
                status = populateTPM2Credentials(*ppServerCredentialsList);

            break;

        default:
            status = ERR_INVALID_ARG;
            break;
    }


exit:
    if (OK != status)
    {
        if (ppServerCredentialsList && *ppServerCredentialsList)
        {
            TAP_UTILS_clearEntityCredentialList(*ppServerCredentialsList);
            DIGI_FREE((void **)ppServerCredentialsList);
        }
    }

    return status;
}
#endif /* __ENABLE_TAP_REMOTE__ */

#endif /* __DISABLE_DIGICERT_TAP_CREDS_FILE__ */
#endif /*!__ENABLE_DIGICERT_TAP__ */

