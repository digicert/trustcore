/*
 * smp_pkcs11_util.c
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
 * @file       smp_pkcs11_util.c
 * @brief      utility file for smp_pkcs11_api.c
 * @details    defines helper and utility functions required by smp_pkcs11_api.c
 */

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_PKCS11__))
#include "../../common/moptions.h"
#include "../../common/mfmgmt.h"
#include "smp_pkcs11_api.h"
#include "smp_pkcs11.h"
#include "../../crypto/pkcs11t.h"
#include "../../tap/tap_utils.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_sha256.h"
#else
#include "../../crypto/sha256.h"
#endif

/* for atoi() */
#include <stdlib.h>
/* for strcpy */
#include <string.h>
/* for sprintf and printf when DB_PRINT is not defined */
#include <stdio.h>

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
#include "../../common/loadlibrary.h"
#endif

#define MAX_OBJECT_SZ 4096

typedef struct attTypes
{
    const char* pszName;
    CK_ULONG    ulType;
    int         nFormat;
    CK_ULONG    ulValueLen;
} attTypes;

/* Global Mutex for protecting pkcs11 modules */
extern RTOS_MUTEX gGemMutex;
/* Global required to store all the pkcs11 modules in the system */
extern Pkcs11_ModuleList* gModListHead;
extern Pkcs11_Config* gConfig;

const ubyte4 tokenPin[MAX_MODULE_SLOTS] = {PIN_LABEL_1, PIN_LABEL_3, PIN_LABEL_4, PIN_LABEL_5, PIN_LABEL_6, PIN_LABEL_7};

/*
 * Init routine called from SMP_PKCS11_register API.
 * Allocate all necessary objects and also initialize module if config
 * file provided and initialize pkcs11 cryptoki library.
 */

MSTATUS PKCS11_init(
        TAP_ConfigInfo *pConfigInfo
)
{
    MSTATUS status = OK;
    Pkcs11_Config* pGemConfig = NULL;
    Pkcs11_ModuleList* pGemModList = NULL;
    const sbyte iniFile[] = "/etc/IDGo800/Pkcs11.PKCS11.ini";

    if (gGemMutex)
    {
        PKCS11_FillError(NULL, &status, ERR_GENERAL, "ERR_GENERAL");
        goto exit;
    }

    DIGI_MEMSET((ubyte*)&gGemMutex, 0x00, sizeof(RTOS_MUTEX));
    status = RTOS_mutexCreate(&gGemMutex, (enum mutexTypes) 0, 1);

    /* If Configuration provided use that */
    if (pConfigInfo)
    {
        if (TAP_PROVIDER_PKCS11 != pConfigInfo->provider)
        {
            PKCS11_FillError(NULL, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
            goto exit;
        }

        if ((pConfigInfo->configInfo.pBuffer) && (pConfigInfo->configInfo.bufferLen))
        {
            ubyte *tmpConf = NULL;
            status = DIGI_MALLOC((void **) &tmpConf, pConfigInfo->configInfo.bufferLen + 1);
            if (OK != status)
                goto exit;

            (void) DIGI_MEMCPY(tmpConf, pConfigInfo->configInfo.pBuffer, pConfigInfo->configInfo.bufferLen);
            tmpConf[pConfigInfo->configInfo.bufferLen] = '\0';
            pGemConfig = PKCS11_parseConf(tmpConf);
            gConfig = pGemConfig;
            if (pGemConfig)
            {
                status = PKCS11_createModuleList(pGemConfig);
            }
            else
            {
                status = ERR_FILE_BAD_DATA;
            }
            (void) DIGI_FREE((void **) &tmpConf);
            if (OK != status)
            {
                goto exit;
            }
        }

        pGemModList = gModListHead;
        while (pGemModList)
        {
            if (pGemModList->moduleId != EMULATED_MODULE_ID)
            {
                PKCS11_parseIni(iniFile, pGemModList->labelStr);
            }
            pGemModList = pGemModList->pNext;
        }
    }

exit:
    return status;
}

/*
 * DeInit routine called from SMP_PKCS11_unregister API.
 * Free all allocations done for the pkcs11 modules and finalize cryptoki library.
 */
MSTATUS PKCS11_deInit(
)
{
    MSTATUS status = OK;
    Pkcs11_ModuleList* pGemModList = NULL;
    Pkcs11_ModuleList* pTmpList = NULL;
    Pkcs11_Module* pGemModule = NULL;
    Pkcs11_Module* pTmpModule = NULL;
    Pkcs11_Token* pGemToken = NULL;
    Pkcs11_Token* pTmpToken = NULL;
    Pkcs11_Object* pGemObject = NULL;
    Pkcs11_Object* pTmpObject = NULL;
    Pkcs11_Config* pTmpConfig = NULL;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;    
#endif

    if (gGemMutex)
    {
        if (OK != (status = RTOS_mutexWait(gGemMutex)))
            goto exit;
    }

    /* Free all the resources inside the pkcs11 smp objects created */
    if (gModListHead)
    {
        pGemModList = gModListHead;
        /* Free module list */
        while (pGemModList)
        {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
            pFuncTable = pGemModList->pFuncTable;
#endif
            pGemModule = pGemModList->pModuleHead;
            /* Free modules */
            while (pGemModule)
            {
                pGemToken = pGemModule->pTokenHead;
                /* Free tokens */
                while (pGemToken)
                {
                    pGemObject = pGemToken->pObjectHead;
                    /* Free objects */
                    while (pGemObject)
                    {
                        pTmpObject = pGemObject;
                        pGemObject = pGemObject->pNext;
                        FREE(pTmpObject);
                    }

                    /* Logout Token session */
                    if (pGemToken->isLoggedIn)
                    {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
                        if (NULL != pFuncTable)
#endif
                            CALL_PKCS11_API(C_Logout, pGemToken->tokenSession);
                    }
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
                    if (NULL != pFuncTable)
#endif
                        CALL_PKCS11_API(C_CloseSession, pGemToken->tokenSession);

                    pTmpToken = pGemToken;
                    pGemToken = pGemToken->pNext;
                    FREE(pTmpToken);
                }

                /* Logout module session */
                if (pGemModule->isLoggedIn)
                {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
                    if (NULL != pFuncTable)
#endif
                        CALL_PKCS11_API(C_Logout, pGemModule->moduleSession);
                }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
                if (NULL != pFuncTable)
#endif
                    CALL_PKCS11_API(C_CloseSession, pGemModule->moduleSession);

                if (pGemModule->error.tapErrorString.pBuffer)
                    FREE(pGemModule->error.tapErrorString.pBuffer);

                pTmpModule = pGemModule;
                pGemModule = pGemModule->pNext;
                FREE(pTmpModule);
            }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
            if (NULL != pFuncTable)
#endif
                CALL_PKCS11_API(C_Finalize, NULL_PTR);
            
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
            if (NULL != pGemModList->pLib)
            {
                (void) DIGICERT_unloadDynamicLibrary(pGemModList->pLib);
            }
#endif
            pTmpList = pGemModList;
            pGemModList = pGemModList->pNext;
            FREE(pTmpList);
        }

        gModListHead = NULL;
    }

    while (NULL != gConfig)
    {
        if (gConfig->modDesc)
        {
            (void) DIGI_FREE((void **)&(gConfig->modDesc));
        }
        if (gConfig->credentialFile.pBuffer)
        {
            (void) DIGI_FREE((void **)&(gConfig->credentialFile.pBuffer));
        }
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
        if (gConfig->modLib)
        {
            (void) DIGI_FREE((void **)&(gConfig->modLib));
        }
#endif
        pTmpConfig = gConfig;
        gConfig = gConfig->pNext;

        (void) DIGI_FREE((void **)&pTmpConfig);
    }

    if (gGemMutex)
    {
        (void) RTOS_mutexRelease(gGemMutex);
        (void) RTOS_mutexFree(&gGemMutex);
        gGemMutex = NULL;
    }

exit:

    return status;
}

MSTATUS PKCS11_logoutAllModuleSessions(
    Pkcs11_Module* pGemModule
)
{
    Pkcs11_Token* token = NULL;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    /* Free pGemModuleule */
    if (pGemModule)
    {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
        pFuncTable = pGemModule->pFuncTable;
        if (NULL == pFuncTable)  /* perhaps the sw module, no error, just no-op */
            goto exit;
#endif
        token = pGemModule->pTokenHead;
        /* Free tokens */
        while (token)
        {
            /* Logout Token session */
            if (token->isLoggedIn)
            {
                CALL_PKCS11_API(C_Logout, token->tokenSession);
                token->isLoggedIn = FALSE;
            }
            token = token->pNext;
        }

        /* Logout pGemModuleule session */
        if (pGemModule->isLoggedIn)
        {
            CALL_PKCS11_API(C_Logout, pGemModule->moduleSession);
            pGemModule->isLoggedIn = FALSE;
        }
    }

exit:

    return OK;
}

MSTATUS PKCS11_closeAllModuleSessions(
        Pkcs11_Module* pGemModule
)
{
    CK_RV rVal = CKR_OK;
    MSTATUS status = OK;
    Pkcs11_Token* token = NULL;
    Pkcs11_Object* object = NULL;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    /* Free pGemModuleule */
    if (pGemModule)
    {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
        pFuncTable = pGemModule->pFuncTable;
#endif        
        token = pGemModule->pTokenHead;
        /* Free tokens */
        while (token)
        {
            object = token->pObjectHead;
            /* Free objects */
            while (object)
            {
                FREE(object);
                object = object->pNext;
            }

            /* Logout Token session */
            if (token->isLoggedIn)
            {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
                if (NULL != pFuncTable)
#endif
                {
                    rVal = CALL_PKCS11_API(C_Logout, token->tokenSession);
                    if (CKR_OK != rVal)
                    {
                        status = PKCS11_nanosmpErr(NULL, rVal);
                        goto exit;
                    }
                }
            }
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
            if (NULL != pFuncTable)
#endif
            {
                rVal = CALL_PKCS11_API(C_CloseSession, token->tokenSession);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(NULL, rVal);
                    goto exit;
                }
            }
            FREE(token);
            token = token->pNext;
        }

        pGemModule->pTokenHead = NULL;
        /* Logout pGemModuleule session */
        if (pGemModule->isLoggedIn)
        {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
            if (NULL != pFuncTable)
#endif
            {
                rVal = CALL_PKCS11_API(C_Logout, pGemModule->moduleSession);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(NULL, rVal);
                    goto exit;
                }
            }
            pGemModule->isLoggedIn = FALSE;
        }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
        if (NULL != pFuncTable)
#endif
        {
            rVal = CALL_PKCS11_API(C_CloseSession, pGemModule->moduleSession);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(NULL, rVal);
                goto exit;
            }
        }
        pGemModule->moduleSession = 0;
    }

exit:
    return status;
}


MSTATUS PKCS11_deleteAllObjects(
        Pkcs11_Module* pGemModule,
        Pkcs11_Token* pGemToken
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_OBJECT_HANDLE objHandle = 0;
    CK_ULONG bFound = FALSE;
    CK_BYTE keyId = (CK_BYTE)PKCS11_OBJECT_ID_START;

    CK_ATTRIBUTE objTemplate = { CKA_ID, &keyId, sizeof(keyId) };

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pGemModule->pFuncTable;  /* caller responsible for pGemModule not null */
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }
#endif

    if (CKR_OK != (rVal = CALL_PKCS11_API(C_FindObjectsInit, pGemToken->tokenSession, NULL_PTR, 0)))
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }

    do
    {
        bFound = 0;
        objTemplate.ulValueLen = sizeof(keyId);
        /* Search for an object */
        if ((rVal = CALL_PKCS11_API(C_FindObjects, pGemToken->tokenSession, &objHandle, 1, &bFound)) != CKR_OK)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            goto exit;
        }

        if (1 == bFound)
        {
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, objHandle, &objTemplate, 1);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(pGemModule, rVal);
                goto exit;
            }

            /*if (label[0] == dummyID)
            {
                 Don't destroy dummy object
                continue;
            }*/

            if (CKR_OK != (rVal = CALL_PKCS11_API(C_DestroyObject, pGemToken->tokenSession, objHandle)))
            {
                status = PKCS11_nanosmpErr(pGemModule, rVal);
                continue;
            }
        }
    } while (1 == bFound);

    if ((rVal = CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession)) != CKR_OK)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }

    while (pGemToken->pObjectHead)
    {
        PKCS11_removeObject(pGemModule, &pGemToken->pObjectHead, pGemToken->pObjectHead);
    }

exit:

    return status;
}

ubyte* PKCS11_fetchStr(
        ubyte* pBuf,
        ubyte* pOutBuf,
        ubyte4 maxLen
)
{
    ubyte4 i = 0;
    ubyte *pVal = pOutBuf;
    ubyte4 size = 0;

    while ((pBuf[i] != '\n')  &&  (pBuf[i] != '\0')  &&  (pBuf[i] != '\r'))
    {
        size++;
        i++;
    }

    if (size > maxLen)
        size = maxLen;

    if (NULL == pVal)
    {
        pVal = MALLOC(size + 1);
        if (NULL == pVal)
        {
            return NULL;
        }
    }
    (void) DIGI_MEMCPY(pVal, pBuf, size);
    pVal[size] = '\0';

    return pVal;
}

ubyte4 PKCS11_fetchInt(
        ubyte* pBuf
)
{
    ubyte4 i = 0;
    sbyte val[8] = {0};
    ubyte4 size = 0;

    while ((pBuf[i] != '\n') && (pBuf[i] != '\0'))
    {
        size++;
        i++;
    }

    if ((size > sizeof(int)) || (size == 0))
        return -1;

    for (i=0; i<size; i++)
        val[i] = pBuf[i];

    return atoi((const char *)val);
}

ubyte* PKCS11_parseString(
        ubyte* pParse,
        ubyte* pBuf
)
{
    int i=0, j=0;

    while (pBuf[i] != '\0')
    {
        /* check case insensitive */
        if (pParse[j] == pBuf[i] || (pBuf[i] <= 'Z' && pParse[j] == (pBuf[i] + ('z' - 'Z'))))
        {
            if (pParse[j+1] == '\0')
            {
                if (pBuf[i+1] == '\n')
                    return &pBuf[i+2];
                else
                    return &pBuf[i+1];
            }
            j++;
        }
        else
        {
            j=0;
        }
        i++;
    }
    return &pBuf[i];
}

static Pkcs11_Config* PKCS11_parseModule(ubyte *pModHead, ubyte *pModEnd)
{
    MSTATUS status = OK;
    Pkcs11_Config *pConf = NULL;
    ubyte moduleId[] = "modulenum=";
    ubyte modDesc[] = "modulename=";
    ubyte moduleIdStr[] = "moduleidstr=";
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    ubyte modulelibpath[] = "modulelibpath=";
#endif
    ubyte credFile[] = "credfile=";
    ubyte *pValString = NULL; 
    ubyte *pBuf = NULL;

    status = DIGI_MALLOC((void **) &pConf, sizeof(Pkcs11_Config));
    if (OK != status)
        goto exit;

    status = ERR_INVALID_INPUT;
    pBuf = PKCS11_parseString(moduleId, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
        goto exit;
    else
        pConf->moduleId = PKCS11_fetchInt(pBuf);
    
    pBuf = PKCS11_parseString(modDesc, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
        goto exit;
    else
        pConf->modDesc = PKCS11_fetchStr(pBuf, NULL, MAX_SLOT_DESC_SZ);

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pBuf = PKCS11_parseString(modulelibpath, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
        goto exit;
    else
        pConf->modLib = PKCS11_fetchStr(pBuf, NULL, MAX_DATA_STORAGE);    
#endif

    pBuf = PKCS11_parseString(moduleIdStr, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
        goto exit;
    else
        pValString = PKCS11_fetchStr(pBuf, NULL, 2*SHA256_RESULT_SIZE);

    /* Convert module id string to HEX */
    if (OK != (status = DIGI_convertHexString(
                    (const char *)pValString,
                    pConf->deviceModuleIdStr,
                    sizeof(pConf->deviceModuleIdStr))))
    {
        DB_PRINT("%s.%d: Error converting ID string \"%s\" to HEX value\n",__FUNCTION__, __LINE__, pValString);
        goto exit;
    }

    /* credFile is optional, status is OK at this point*/
    pBuf = PKCS11_parseString(credFile, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
    {
        pConf->credentialFile.pBuffer = NULL;
        pConf->credentialFile.bufferLen = 0;
    }
    else
    {
        pConf->credentialFile.pBuffer = PKCS11_fetchStr(pBuf, NULL, MAX_SLOT_DESC_SZ);
        pConf->credentialFile.bufferLen = DIGI_STRLEN((sbyte*)pConf->credentialFile.pBuffer);
    }

exit:

    if (NULL != pValString)
    {
        (void) DIGI_FREE((void **) &pValString);
    }

    if (OK != status && NULL != pConf)
    {
        (void) DIGI_FREE((void **) &pConf);
    }

    return pConf;
}

/* Parse pkcs11 config file */
Pkcs11_Config* PKCS11_parseConf(
    ubyte* pBufHead
)
{
    MSTATUS status = OK;
    ubyte provider[] = "providertype=";
    ubyte module[] = "[module]";
    ubyte *pModHead = NULL;
    ubyte *pModEnd = NULL;
    struct Pkcs11_Config *pConf = NULL, *pHead = NULL, *pNewConf = NULL;
    byteBoolean done = FALSE;

    /* validate providertype if it's part of the config */
    pModHead = PKCS11_parseString(provider, pBufHead);
    if (*pModHead !='\0')
    {
        ubyte4 providerType = PKCS11_fetchInt(pModHead);
        if (TAP_PROVIDER_PKCS11 != providerType)
        {
            DB_PRINT("%s.%d: Provider value %d in config is not PKCS11.\n",__FUNCTION__, __LINE__, providerType);
            goto exit;
        }
    }
    else  /* reset pModHead */
    {
        pModHead = pBufHead;
    }

    while(!done)
    {
        /* look for where the next module begins */
        pModHead = PKCS11_parseString(module, pModHead);
        if (*pModHead == '\0')
        {
            status = ERR_INVALID_INPUT;
            break;
        }

        /* look for the next module */
        pModEnd = PKCS11_parseString(module, pModHead);
        if (*pModEnd == '\0')
        {
            done = TRUE;
        }
        else
        {
            /* we'll go back before the 9 char [module]\n directive */
            pModEnd -= 9;
        }

        /* whether pModEnd is the buffer end or another module, copy over this module config */
        pNewConf = PKCS11_parseModule(pModHead, pModEnd);
        if (NULL == pNewConf)
        {
            DB_PRINT("%s.%d: Error parsing [module].\n",__FUNCTION__, __LINE__);
            goto exit;            
        }
        pNewConf->pNext = NULL;

        if (NULL == pHead)
        {
            pHead = pNewConf;
        }
        else
        {
            pConf->pNext = pNewConf;
        }

        if (done)
        {
            break;
        }
        else
        {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
            /* move to the next module, begin after the last [module] directive */
            pConf = pNewConf;
            pModHead = pModEnd;
#else
            /* we allow only one [module]. Error */
            status = ERR_INVALID_INPUT;
            DB_PRINT("%s.%d: Multiple [module]s found but dynamic loading is not enabled.\n",__FUNCTION__, __LINE__);
            break;
#endif
        }
    }

exit:

    if (OK != status)
    {
        pConf = pHead;
        while (NULL != pConf)
        {
            /* re-use pNewConf as pNext */
            pNewConf = pConf->pNext;
            (void )DIGI_FREE((void **) &pConf);
            pConf = pNewConf;
        }
        pHead = NULL;
    }

    return pHead;
}

MSTATUS PKCS11_parseIni(
    const sbyte* pIniFile,
    ubyte pLabels[][MAX_LABEL_DESC_SZ]
)
{
    MSTATUS status = OK;
    ubyte label[] = "[LABEL]";
    ubyte pin[] = "PIN_x=";
    ubyte4 i = 0;
    const ubyte4 pinNum = 4;
    const ubyte4 StartPin = 3;
    const ubyte4 LastPin = 7;

    FileDescriptor fp = NULL;
    ubyte4 fileLen = 0;
    ubyte* pBuf = NULL;

    status = FMGMT_fopen (pIniFile, (const sbyte *) "r", &fp);
    if (OK != status)
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    FMGMT_fseek (fp, 0, MSEEK_END);
    FMGMT_ftell (fp, &fileLen);
    FMGMT_fseek (fp, 0, MSEEK_SET);

    pBuf = MALLOC(fileLen + 1);
    if (NULL == pBuf)
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    FMGMT_fread (pBuf, 1, fileLen, fp, &fileLen);
    pBuf[fileLen] = '\0';


    pBuf = PKCS11_parseString(label, pBuf);
    if (*pBuf == '\0')
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    for (i=StartPin; i<=LastPin; i++)
    {
        pin[pinNum] = i + 0x30;
        pBuf = PKCS11_parseString(pin, pBuf);
        if (*pBuf =='\0')
            goto exit;

        PKCS11_fetchStr(pBuf, pLabels[i-StartPin], MAX_LABEL_DESC_SZ-1);
    }

exit:
    if (NULL != fp)
        FMGMT_fclose (&fp);

    return status;
}

void PKCS11_fetchTokenLabel(
            ubyte4 mainSlotId,
            ubyte4 tokenId,
            ubyte* tokLabelStr
)
{

    Pkcs11_ModuleList* gModList = gModListHead;

    while((gModList) && (gModList->phySlotId != mainSlotId))
    {
        gModList = gModList->pNext;
    }

    if (gModList)
    {
        strncpy((char *)tokLabelStr, (const char *)gModList->labelStr[tokenId-1], MAX_LABEL_DESC_SZ - 1);
    }
}

/* Copy the Slot Description */
MSTATUS PKCS11_copySlotDesc(
            CK_CHAR* pCopySlotDesc,
            CK_CHAR* pSlotDesc,
            ubyte4 size
)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    if ((NULL == pCopySlotDesc) || (NULL == pSlotDesc))
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    for (i = 0; i < size; i++)
    {
        if (pSlotDesc[i] == ' ' && ( (i == size - 1) || pSlotDesc[i+1] == ' ') )
            break;

        pCopySlotDesc[i] = pSlotDesc[i];
    }

exit:

    return status;
}

/* Check Substring */
byteBoolean PKCS11_checkSubString(
        CK_CHAR* pStr,
        CK_CHAR* pSubStr
)
{
    byteBoolean bResult = FALSE;
    CK_CHAR *p1, *p2, *p3;

    if ((NULL == pStr) || (NULL == pSubStr))
       goto exit;

    p1 = pStr;
    while ('\0' != *p1)
    {
        p2 = pSubStr;
        if (*p1 == *p2)
        {
            p3 = p1;
            while ((('\0' != *p3)) && (('\0' != *p2)) && ((*p3 == *p2)))
            {
                p3++;p2++;
            }

            if (('\0' == *p2))
            {
                bResult = TRUE;
                goto exit;
            }
        }
        p1++;
     }

exit:
    return bResult;
}


/* Fetch the Pin Description of the SlotId */
MSTATUS PKCS11_fetchPinDesc(
        Pkcs11_Module* pGemModule,
        ubyte4 slotId,
        ubyte* sPinDesc
        )
{
    ubyte4 j=0, k=0;
    CK_RV rVal = CKR_OK;
    MSTATUS status = OK;
    CK_TOKEN_INFO tInfo;

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pGemModule->pFuncTable;  /* caller responsible for pGemModule not null */
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }
#endif

    /* Get the token info for pin Description */
    rVal = CALL_PKCS11_API(C_GetTokenInfo, slotId, &tInfo);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }

    DIGI_MEMSET((ubyte*)sPinDesc, 0, MAX_DESC_SZ);

    /* fetch the Pin Description which is concatinated in brackets */
    for(j = 0; j < (MAX_DESC_SZ - 1); j++)
    {
        if (tInfo.label[j] == '(')
        {
            if (j == (MAX_DESC_SZ - 2) || tInfo.label[++j] == ')')
                break;

            do {
                sPinDesc[k++] = tInfo.label[j++];
            } while (j < (MAX_DESC_SZ - 1) && tInfo.label[j] != ')' && tInfo.label[j] != '\0');

            break;
        }
    }

exit:
    return status;
}

/* validates the id in pNew hasn't already been used */
static MSTATUS validateId(Pkcs11_ModuleList *pNew, Pkcs11_ModuleList *pHead)
{
    Pkcs11_ModuleList *pCurrent = pHead;

    while ( (uintptr) pCurrent != (uintptr) pNew )
    {
        if (pCurrent->moduleId == pNew->moduleId)
            return ERR_INVALID_INPUT;

        pCurrent = pCurrent->pNext;
    }
    
    return OK;
}

/* If possible sets a runtime usable flag for the library type based on the libpath */
static void PKCS11_getLibType(ubyte *pLibPath, PKCS11_LIBTYPE *pLibType)
{
    char *pSoftHsm = "libsofthsm2.so";
    char *pCloudHsm = "libcloudhsm_pkcs11.so";
    char *pDssm = "smpkcs11.so";
    ubyte4 pathLen = DIGI_STRLEN((const sbyte *) pLibPath);
    sbyte4 cmp = -1;
  
    if (pathLen >= 14)
    {
        (void) DIGI_MEMCMP(pLibPath + pathLen - 14, (ubyte *) pSoftHsm, 14, &cmp);
        if (0 == cmp)
        {
            *pLibType = LIBTYPE_SOFTHSM2;
            return;
        }
    }

    if (pathLen >= 21)
    {
        (void) DIGI_MEMCMP(pLibPath + pathLen - 21, (ubyte *) pCloudHsm, 21, &cmp);
        if (0 == cmp)
        {
            *pLibType = LIBTYPE_CLOUDHSM;
            return;
        }
    }

    if (pathLen >= 11)
    {
        (void) DIGI_MEMCMP(pLibPath + pathLen - 11, (ubyte *) pDssm, 11, &cmp);
        if (0 == cmp)
        {
            *pLibType = LIBTYPE_DSSM;
            return;
        }
    }
    
    *pLibType = LIBTYPE_UNKNOWN; /* default */
    return;
}

/* Create pkcs11 module list using configuration or by searching Pkcs11 Slots */
MSTATUS PKCS11_createModuleList(
        Pkcs11_Config* pGemConfigHead
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;

    ubyte4 i = 0;
    ubyte4 modCount = 0;
    CK_SLOT_ID_PTR pSlotList = NULL;
    Pkcs11_ModuleList* pModList = NULL;
    Pkcs11_ModuleList* pTmpList = NULL;
    CK_ULONG count = 0;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
    CK_CHAR slotDesc[MAX_SLOT_DESC_SZ] = {0};
    CK_CHAR mainSlotDesc[MAX_SLOT_DESC_SZ] = {0};
    ubyte serialNumber[SHA256_HASH_LENGTH] = {0};
    Pkcs11_Config* pGemConfig = NULL;
    sbyte4 cmpResult = -1;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_RV (*funcPtr)(CK_FUNCTION_LIST_PTR_PTR);
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;    
#endif

    /* Create module 0 for software crypto */
    if (NULL == gModListHead)
    {
        pModList = gModListHead = MALLOC(sizeof(Pkcs11_ModuleList));
        if (NULL == pModList)
        {
            PKCS11_FillError(NULL, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
            goto exit;
        }
        DIGI_MEMSET((ubyte*)pModList, 0, sizeof(Pkcs11_ModuleList));
        pModList->phySlotId = -1;
        pModList->moduleId = modCount++;
    }
    else
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Module List already created. Can't create twice.\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    if (NULL != pGemConfigHead)
    {
        /* Allocate each module and check the slots */

        pGemConfig = pGemConfigHead;
        while (NULL != pGemConfig)
        {
            pModList->pNext = MALLOC(sizeof(Pkcs11_ModuleList));
            if (NULL == pModList->pNext)
            {
                PKCS11_FillError(NULL, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                goto exit;
            }
            pModList = pModList->pNext;
            DIGI_MEMSET((ubyte*)pModList, 0, sizeof(Pkcs11_ModuleList));

            pModList->moduleId = pGemConfig->moduleId;
            status = validateId(pModList, gModListHead);
            if (OK != status)
            {
                DB_PRINT("%s.%d: multiple [module]'s with the same id: %d\n",__FUNCTION__, __LINE__, pModList->moduleId);
                goto exit;
            }
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
            status = DIGICERT_loadDynamicLibraryEx((const char *) pGemConfig->modLib, &pModList->pLib);
            if (OK != status)
            {
                DB_PRINT("%s.%d: Unable to open PKCS11 Library: %s status = %d\n",__FUNCTION__, __LINE__, pGemConfig->modLib, status);
                goto exit;
            }

            PKCS11_getLibType(pGemConfig->modLib, &pModList->libType);

            status = DIGICERT_getSymbolFromLibrary("C_GetFunctionList", pModList->pLib, (void **) &funcPtr);
            if (OK != status)
            {
                DB_PRINT("%s.%d: Unable to find method C_GetFunctionList in PKCS11 Library: %s status = %d\n",
                         __FUNCTION__, __LINE__, pGemConfig->modLib, status);
                goto exit;
            }

            rVal = funcPtr(&pModList->pFuncTable);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(NULL, rVal);
                DB_PRINT("%s.%d: Error retrieving function pointer table in PKCS11 Library: %s status = %d\n",
                        __FUNCTION__, __LINE__, pGemConfig->modLib, status);
                goto exit;
            }

            pFuncTable = pModList->pFuncTable;
#endif
            /* call initialize */
            rVal = CALL_PKCS11_API(C_Initialize, NULL_PTR);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(NULL, rVal);
                goto exit;
            }

            /* Get number of slots in system */
            rVal = CALL_PKCS11_API(C_GetSlotList, CK_TRUE, NULL_PTR, &count);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(NULL, rVal);
                goto exit;
            }
            
            if (0 == count)
            {
                PKCS11_FillError(NULL, &status, ERR_INVALID_INPUT, "ERR_INVALID_INPUT");
                goto exit;
            }

            if (NULL != pSlotList)
            {
                status = DIGI_FREE((void **) &pSlotList);
                if (OK != status)
                    goto exit;
            }

            status = DIGI_MALLOC((void **) &pSlotList, count * sizeof(CK_SLOT_ID));
            if (OK != status)
                goto exit;

            /* Now Get the complete slot list */
            rVal = CALL_PKCS11_API(C_GetSlotList, CK_TRUE, pSlotList, &count);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(NULL, rVal);
                goto exit;
            }

            (void) DIGI_MEMSET((ubyte*)mainSlotDesc, 0, MAX_SLOT_DESC_SZ);

            /* Fetch the main slots in the system and create a list for them */
            for (i=0; i<count; i++)
            {
                (void) DIGI_MEMSET((ubyte*)&slotInfo, 0, sizeof(CK_SLOT_INFO));
                rVal = CALL_PKCS11_API(C_GetSlotInfo, pSlotList[i], &slotInfo);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(NULL, rVal);
                    goto exit;
                }

                (void) DIGI_MEMSET((ubyte*)slotDesc, 0, MAX_SLOT_DESC_SZ);
                status = PKCS11_copySlotDesc(slotDesc, slotInfo.slotDescription, MAX_SLOT_DESC_SZ - 1);
                if (OK != status)
                {
                    goto exit;
                }

                if (0 == DIGI_STRCMP((const sbyte *)pGemConfig->modDesc, (const sbyte *)slotDesc))
                {
                    /* validate the slotid */
                    rVal = CALL_PKCS11_API(C_GetTokenInfo, pSlotList[i], &tokenInfo);
                    if (CKR_OK != rVal)
                    {
                        status = PKCS11_nanosmpErr(NULL, rVal);
                        DB_PRINT("%s.%d Failed to get tokeninfo. status=%d\n",
                                __FUNCTION__, __LINE__, status);
                        goto exit;
                    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    if (OK != (status = CRYPTO_INTERFACE_SHA256_completeDigest(tokenInfo.serialNumber, PKCS11_SERIAL_NO_BUF_LEN, serialNumber)))
#else
                    if (OK != (status = SHA256_completeDigest(tokenInfo.serialNumber, PKCS11_SERIAL_NO_BUF_LEN, serialNumber)))
#endif
                    {
                        DB_PRINT("%s.%d Failed to copy buffer. status=%d\n",
                                __FUNCTION__, __LINE__, status);
                        goto exit;
                    }

            #ifdef __ENABLE_DIGICERT_SMP_PKCS11_DUMP_MODULE_IDS__
                    DB_PRINT("Slot %d moduleidstr: ", i);
                    for (i = 0; i < SHA256_HASH_LENGTH; i++)
                    {
                        DB_PRINT("%02x", serialNumber[i]);
                    }
                    DB_PRINT("\n");
            #endif

                    status = DIGI_MEMCMP(serialNumber, pGemConfig->deviceModuleIdStr, sizeof(pGemConfig->deviceModuleIdStr), 
                                        &cmpResult);

                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Error comparing ModuleId's, status = %d\n",
                                __FUNCTION__, __LINE__, (int)status);

                        goto exit;
                    }
                    if (cmpResult)
                    {
                        DB_PRINT("%s.%d Module ID string check failed, device module id string "
					             "does not match one in configuration file\n\n", __FUNCTION__, __LINE__);

                        DB_PRINT("Slot %d moduleidstr: ", i);
                        for (i = 0; i < SHA256_HASH_LENGTH; i++)  /* ok to re-use i */
                        {
                            DB_PRINT("%02x", serialNumber[i]);
                        }
                        DB_PRINT("\n\nModule Id %d DeviceID string set to => ", pGemConfig->moduleId);
                        for(i = 0; i < sizeof(pGemConfig->deviceModuleIdStr); i++)
                        {
                            DB_PRINT("%02x", pGemConfig->deviceModuleIdStr[i]);
                        }
                        DB_PRINT("\n");
                        goto exit;
                    }

                    pModList->phySlotId = pSlotList[i];
                    break;
                }
            }

            if (count == i)
            {
                status = ERR_INVALID_INPUT;
                DB_PRINT("%s.%d: No slot found for configuration modulename.\n",__FUNCTION__, __LINE__);
                goto exit;
            }

            pGemConfig = pGemConfig->pNext;
        } 
    }
    else
    {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d: No Configurations found. At least one is required for dynamic library load.\n",__FUNCTION__, __LINE__);
#else
        /* call initialize */
        rVal = CALL_PKCS11_API(C_Initialize, NULL_PTR);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(NULL, rVal);
            goto exit;
        }

        /* Get number of slots in system */
        rVal = CALL_PKCS11_API(C_GetSlotList, CK_TRUE, NULL_PTR, &count);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(NULL, rVal);
            goto exit;
        }

        pSlotList = (CK_SLOT_ID_PTR)MALLOC(count * sizeof(CK_SLOT_ID));
        if (NULL == pSlotList)
        {
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
            goto exit;
        }

        /* Now Get the complete slot list */
        rVal = CALL_PKCS11_API(C_GetSlotList, CK_TRUE, pSlotList, &count);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(NULL, rVal);
            goto exit;
        }

        if (0 == count)
        {
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
            goto exit;
        }

        DIGI_MEMSET((ubyte*)mainSlotDesc, 0, MAX_SLOT_DESC_SZ);
        /* Fetch the main slots in the system and create a list for them */
        for (i=0; i<count; i++)
        {
            DIGI_MEMSET((ubyte*)&slotInfo, 0, sizeof(CK_SLOT_INFO));
            rVal = CALL_PKCS11_API(C_GetSlotInfo, pSlotList[i], &slotInfo);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(NULL, rVal);
                goto exit;
            }

            DIGI_MEMSET((ubyte*)slotDesc, 0, MAX_SLOT_DESC_SZ);
            status = PKCS11_copySlotDesc(slotDesc, slotInfo.slotDescription, MAX_SLOT_DESC_SZ - 1);
            if (OK != status)
            {
                goto exit;
            }

            if (TRUE == PKCS11_checkSubString(slotDesc, (CK_CHAR*)MODULE_NAME))
            {
                if (slotInfo.flags & CKF_TOKEN_PRESENT)
                {
                    /* If substring matches then it is a virtual Slot so continue */
                    if (TRUE == PKCS11_checkSubString(slotDesc, mainSlotDesc))
                    {
                        continue;
                    }
                    else
                    {
                        /* Copy the Physical Slot Description for comparisions with virtual Slot Descriptions */
                        (void) DIGI_MEMCPY((void *)mainSlotDesc, (void *)slotDesc, MAX_SLOT_DESC_SZ);

                        /* Found the physical Slot, add it in the List */
                        pModList->pNext = MALLOC(sizeof(Pkcs11_ModuleList));
                        if (NULL == pModList->pNext)
                        {
                            PKCS11_FillError(NULL, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                            goto exit;
                        }
                        pModList = pModList->pNext;
                        DIGI_MEMSET((ubyte*)pModList, 0, sizeof(Pkcs11_ModuleList));
                        pModList->moduleId = modCount++;
                        pModList->phySlotId = pSlotList[i];
                    }
                }
            }
        }
#endif
    }

exit:

    if (OK != status)
    {
        pModList = gModListHead;
        while (pModList)
        {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
            if (NULL != pModList->pLib)
            {
                (void) DIGICERT_unloadDynamicLibrary(pModList->pLib);
            }
#endif
            pTmpList = pModList->pNext;
            (void) DIGI_FREE((void **) &pModList);
            pModList = pTmpList;
        }
        gModListHead = NULL;
    }

    if (NULL != pSlotList)
    {
        (void) DIGI_FREE((void **) &pSlotList);
    }

    return status;
}

TAP_Credential* PKCS11_fetchCredentialFromEntityList(
        TAP_EntityCredentialList *pEntityCredentialList,
        TAP_CREDENTIAL_CONTEXT pwdType
)
{
    ubyte4 i = 0, j = 0;
    TAP_Credential *pCredential = NULL;
    TAP_CredentialList credentialList = {0};

    if ((NULL == pEntityCredentialList) || (NULL == pEntityCredentialList->pEntityCredentials))
        goto exit;

    for(i = 0; i < pEntityCredentialList->numCredentials; i++)
    {
        credentialList = pEntityCredentialList->pEntityCredentials[i].credentialList;
        if (NULL != credentialList.pCredentialList)
        {
            for (j = 0; j < credentialList.numCredentials; j++)
            {
                if ((TAP_CREDENTIAL_TYPE_PASSWORD == credentialList.pCredentialList[j].credentialType) &&
                        (TAP_CREDENTIAL_FORMAT_PLAINTEXT == credentialList.pCredentialList[j].credentialFormat) &&
                        (pwdType == credentialList.pCredentialList[j].credentialContext))
                {
                    pCredential = &credentialList.pCredentialList[j];
                    break;
                }
            }
        }
    }

exit:
    return pCredential;
}

/* Fetch the Credential from the List */
TAP_Credential* PKCS11_fetchCredentialFromList(
        TAP_CredentialList *pCredentials,
        TAP_CREDENTIAL_CONTEXT pwdType
)
{
    ubyte4 i = 0;
    TAP_Credential* pCredential = NULL;

    if ((NULL == pCredentials) || (NULL == pCredentials->pCredentialList))
        goto exit;

    for (i=0; i<pCredentials->numCredentials; i++)
    {
        if ((TAP_CREDENTIAL_TYPE_PASSWORD == pCredentials->pCredentialList[i].credentialType) &&
            (TAP_CREDENTIAL_FORMAT_PLAINTEXT == pCredentials->pCredentialList[i].credentialFormat) &&
            (pwdType == pCredentials->pCredentialList[i].credentialContext))
        {
            pCredential = &pCredentials->pCredentialList[i];
            break;
        }
    }

exit:
    return pCredential;
}

/* Fetch the Attribute Value from the list */
void* PKCS11_fetchAttributeFromIdx(
        TAP_AttributeList* pAttributeList,
        TAP_ATTR_TYPE type,
        ubyte4 idx,
        ubyte4* pLength
)
{
    void *pAttr = NULL;

    if ((NULL == pAttributeList) || (idx >= pAttributeList->listLen))
        goto exit;


    if (pAttributeList->pAttributeList[idx].type == type)
    {
        pAttr = pAttributeList->pAttributeList[idx].pStructOfType;
        if (pLength)
            *pLength = pAttributeList->pAttributeList[idx].length;
    }

exit:
    return pAttr;
}

/* Fetch the Attribute Value from the list */
void* PKCS11_fetchAttributeFromList(
        TAP_AttributeList* pAttributeList,
        TAP_ATTR_TYPE type,
        ubyte4* pLength
)
{
    void* pAttr = NULL;
    ubyte4 i = 0;

    if (NULL == pAttributeList)
        goto exit;

    for (i=0; i<pAttributeList->listLen; i++)
    {
        if (pAttributeList->pAttributeList[i].type == type)
        {
            pAttr = pAttributeList->pAttributeList[i].pStructOfType;
            if (pLength)
                *pLength = pAttributeList->pAttributeList[i].length;
            break;
        }

    }

exit:
    return pAttr;
}

/* Find the Module for the session handle passed */
Pkcs11_Module* PKCS11_findModule(
        CK_SESSION_HANDLE hSession
)
{
    Pkcs11_ModuleList* pModList = NULL;
    Pkcs11_Module* pGemModule = NULL;

    if (!hSession)
    {
        goto exit;
    }

    pModList = gModListHead;
    while (pModList)
    {
        pGemModule = pModList->pModuleHead;
        while (pGemModule)
        {
            /* If Found exit from there */
            if (pGemModule->moduleSession == hSession)
            {
                goto exit;
            }
            pGemModule = pGemModule->pNext;
        }
        pModList = pModList->pNext;
    }

exit:
    return pGemModule;
}

/* Find the token for the session handle passed */
Pkcs11_Token* PKCS11_findToken(
        CK_SESSION_HANDLE hSession
)
{
    Pkcs11_ModuleList* pModList = NULL;
    Pkcs11_Module* pGemModule = NULL;
    Pkcs11_Token* pToken = NULL;

    if (!hSession)
    {
        goto exit;
    }

    pModList = gModListHead;
    while (pModList)
    {
        pGemModule = pModList->pModuleHead;
        while (pGemModule)
        {
            pToken = pGemModule->pTokenHead;
            while (pToken)
            {
                /* If Found exit from there */
                if (pToken->tokenSession == hSession)
                {
                    goto exit;
                }
                pToken = pToken->pNext;
            }
            pGemModule = pGemModule->pNext;
        }
        pModList = pModList->pNext;
    }

exit:
    return pToken;
}

/* Generate the next object Id */
TAP_Buffer PKCS11_generateNextObjectId(
    Pkcs11_Module *pGemModule,
    Pkcs11_Token* pGemToken,
    CK_OBJECT_CLASS obj
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_ULONG objFound = 0;
    CK_OBJECT_HANDLE objHandle = 0;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    TAP_Buffer newId = {0};
    CK_BYTE idBuf[sizeof(TAP_ObjectId)] = {0};
    CK_ATTRIBUTE attrTemplate[] = {
        {CKA_ID, idBuf, sizeof(idBuf)}
    };
    CK_ATTRIBUTE *searchTemp = NULL;
    ubyte4 templateCount = 0;
    ubyte4 i = 0;

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pGemModule->pFuncTable;  /* caller responsible for pGemModule not null */
    if (NULL == pFuncTable)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INTERNAL_ERROR, "ERR_INTERNAL_ERROR");
        goto exit;
    }
#endif

    if ((NULL == pGemToken) || (!&pGemToken->tokenSession))
        goto exit;

    searchTemp = attrTemplate;
    templateCount = 1;

    do
    {
        status = RANDOM_numberGenerator(g_pRandomContext, idBuf, sizeof(idBuf));
        if (OK != status)
        {
            DB_PRINT("%s.%d: Could not generate random bytes for ID.\n",__FUNCTION__, __LINE__);
            goto exit;
        }
        
        /* check for all zeros */
        for (i = 0; i < sizeof(idBuf); i++)
        {
            if (idBuf[i])
                break;
        }
        if (i == sizeof(idBuf))
        {
            /* all zeros, no point in trying again, RNG probably broken */
            status = ERR_TAP_GET_RANDOM_NUM_FAILED;
            DB_PRINT("%s.%d: Could not generate random bytes for ID, status = %d\n",__FUNCTION__, __LINE__, status);
            goto exit;
        }

        objFound = 0;
        rVal = CALL_PKCS11_API(C_FindObjectsInit, pGemToken->tokenSession, searchTemp, templateCount);
        if (CKR_OK != rVal)
        {
            goto exit;
        }

        rVal = CALL_PKCS11_API(C_FindObjects, pGemToken->tokenSession, &objHandle, 1, &objFound);
        if (CKR_OK != rVal)
        {
            goto exit;
        }

        CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);
    } while (0 != objFound);

    /* Found an unused id, copy it over */
    rVal = (CK_RV) DIGI_CALLOC((void **) &newId.pBuffer, 1, attrTemplate[0].ulValueLen);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Allocation Error.\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    newId.bufferLen = attrTemplate[0].ulValueLen;

    rVal = (CK_RV) DIGI_MEMCPY(newId.pBuffer, (ubyte *) idBuf, newId.bufferLen);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Internal Error.\n",__FUNCTION__, __LINE__);
    }

exit:

    if (CKR_OK != rVal)
    {   
        (void) CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);

        if (NULL != newId.pBuffer)
        {
            (void) DIGI_MEMSET_FREE((ubyte **) &newId.pBuffer, newId.bufferLen);
        }
    }
    
    return newId;
}

static sbyte4 objectIdCmp(TAP_Buffer id1, TAP_Buffer id2)
{
    ubyte4 i = 0;

    if (id1.bufferLen < id2.bufferLen)
        return -1;
    else if (id1.bufferLen > id2.bufferLen)
        return 1;
    
    for (i = 0; i < id1.bufferLen; i++)
    {
        if (id1.pBuffer[i] < id2.pBuffer[i])
            return -1;
        else if (id1.pBuffer[i] > id2.pBuffer[i])
            return 1;
    }

    return 0;
}

/* Sort and Add a new object */
MSTATUS PKCS11_addNewObject(
        Pkcs11_Module* pGemModule,
        Pkcs11_Object** pObjectHead,
        Pkcs11_Object* pNewObject
)
{
    MSTATUS status = OK;
    byteBoolean bFound = FALSE;
    Pkcs11_Object* pObject = NULL;
    Pkcs11_Object* pPrevObject = NULL;

    if ((NULL == pObjectHead) || (NULL == pNewObject))
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    if (!(*pObjectHead))
    {
        *pObjectHead = pNewObject;
    }
    else
    {
        pObject = *pObjectHead;

        while (pObject)
        {
            if ( 0 > objectIdCmp(pNewObject->objectId, pObject->objectId) )
            {
                if (pObject == *pObjectHead)
                {
                    *pObjectHead = pNewObject;
                }
                else
                {
                    pPrevObject->pNext = pNewObject;
                }

                pNewObject->pNext = pObject;
                bFound = TRUE;
                break;
            }
            else if (0 == objectIdCmp(pNewObject->objectId, pObject->objectId) )
            {
                status = ERR_GENERAL;
                goto exit;
            }
            pPrevObject = pObject;
            pObject = pObject->pNext;
        }

        if (FALSE == bFound)
        {
            pPrevObject->pNext = pNewObject;
        }
    }

exit:
    return status;
}

/* Remove a object from the object list */
MSTATUS PKCS11_removeObject(
        Pkcs11_Module* pGemModule,
        Pkcs11_Object** pObjectHead,
        Pkcs11_Object* pRemObject
)
{
    MSTATUS status = OK;
    Pkcs11_Object* pObject = NULL;
    Pkcs11_Object* pPrevObj = NULL;

    if ((NULL == pObjectHead) || (NULL == pRemObject))
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    pPrevObj = pObject = *pObjectHead;
    while ((NULL != pObject) && (pObject != pRemObject))
    {
        pPrevObj = pObject;
        pObject = pObject->pNext;
    }

    if (pObject)
    {
        pObject->refCount--;
        if (0 == pObject->refCount) /* no more referenes, remove it from the list */
        {
            /* Remove the token from the list */
            if (pObject == *pObjectHead)
                *pObjectHead = pObject->pNext;
            else
                pPrevObj->pNext = pObject->pNext;

            if (NULL != pObject->objectId.pBuffer)
            {
                (void) DIGI_MEMSET_FREE(&pObject->objectId.pBuffer, pObject->objectId.bufferLen);
                pObject->objectId.bufferLen = 0;
            }
            (void) DIGI_FREE((void **) &pObject);
        }
    }

exit:
    return status;
}

MSTATUS PKCS11_getObjectHandles(Pkcs11_Module *pGemModule,
                                Pkcs11_Token *pGemToken,
                                TAP_Buffer objectId,
                                CK_OBJECT_HANDLE *pprvHandle,
                                CK_OBJECT_HANDLE *ppubHandle)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_ULONG objFound = 0;
    CK_OBJECT_HANDLE objHandle = 0;
    CK_UTF8CHAR label[MAX_ID_BYTE_SIZE] = {0};
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    ubyte privFound = FALSE;
    ubyte pubFound = FALSE;
    ubyte secFound = FALSE;

    CK_ATTRIBUTE classTemplate[] = {
        {CKA_CLASS, &dataClass, sizeof(dataClass)}
    };
    CK_ATTRIBUTE attrTemplate[] = {
        {CKA_ID, &label, sizeof(label)-1}
    };

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pGemModule->pFuncTable;  /* caller responsible for pGemModule not null */
    if (NULL == pFuncTable)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INTERNAL_ERROR, "ERR_INTERNAL_ERROR");
        goto exit;
    }
#endif

    if ((NULL == pprvHandle) ||
        (NULL == ppubHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. status=%d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (objectId.bufferLen > (MAX_ID_BYTE_SIZE - 1))
    {
        DB_PRINT("%s.%d: Input ID size too large.\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    rVal = (CK_RV) DIGI_MEMCPY((ubyte *) label, objectId.pBuffer, objectId.bufferLen);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Internal Error.\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    attrTemplate[0].ulValueLen = objectId.bufferLen;

    rVal = CALL_PKCS11_API(C_FindObjectsInit, pGemToken->tokenSession, attrTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        DB_PRINT("%s.%d Failed to init object search operation. status=%d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    do
    {
        objFound = 0;
        rVal = CALL_PKCS11_API(C_FindObjects, pGemToken->tokenSession, &objHandle, 1, &objFound);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(NULL, rVal);
            DB_PRINT("%s.%d Failed in object search operation. status=%d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        if ((CKR_OK == rVal)  && (objFound))
        {
            dataClass = 0;
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, objHandle, classTemplate, 1);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(NULL, rVal);
                DB_PRINT("%s.%d Failed in object search operation. status=%d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }

            switch(dataClass)
            {
                case CKO_PRIVATE_KEY:
                {
                    if (TRUE == privFound)
                    {
                        *ppubHandle = 0;
                        *pprvHandle = 0;
                        status = ERR_INTERNAL_ERROR;
                        DB_PRINT(
                            "%s.%d: More than two objects with the same CKA_ID have been found. \
                            Please use PKCS11 key management utilities to restore key id consistency.\n",
                            __FUNCTION__, __LINE__);
                        goto exit;
                    }
                    else
                    {
                        privFound = TRUE;
                    }

                    *pprvHandle = objHandle;
                }
                break;

                case CKO_PUBLIC_KEY:
                {
                    if (TRUE == pubFound)
                    {
                        *ppubHandle = 0;
                        *pprvHandle = 0;
                        status = ERR_INTERNAL_ERROR;
                        DB_PRINT(
                            "%s.%d: More than two objects with the same CKA_ID have been found. \
                            Please use PKCS11 key management utilities to restore key id consistency.\n",
                            __FUNCTION__, __LINE__);
                        goto exit;
                    }
                    else
                    {
                        pubFound = TRUE;
                    }

                    *ppubHandle = objHandle;
                }
                break;

                case CKO_SECRET_KEY:
                {
                    if (TRUE == secFound)
                    {
                        *ppubHandle = 0;
                        *pprvHandle = 0;
                        status = ERR_INTERNAL_ERROR;
                        DB_PRINT(
                            "%s.%d: More than two objects with the same CKA_ID have been found. \
                            Please use PKCS11 key management utilities to restore key id consistency.\n",
                            __FUNCTION__, __LINE__);
                        goto exit;
                    }
                    else
                    {
                        secFound = TRUE;
                    }

                    *pprvHandle = objHandle;
                    *ppubHandle = objHandle;
                }
                break;
            }
        }

    } while(objFound);

    rVal = CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        DB_PRINT("%s.%d Failed in finalize object search operation. status=%d\n",
                 __FUNCTION__, __LINE__, status);
    }

exit:
    return status;
}

/* Return the object Handle for the object Id passed */
Pkcs11_Object* PKCS11_findAndAllocObject(
    Pkcs11_Module *pGemModule,
    Pkcs11_Token *pGemToken,
    TAP_Buffer objectId
)
{
    CK_RV rVal = CKR_OK;
    CK_ULONG i = 0;
    CK_ULONG objFound = 0;
    CK_OBJECT_HANDLE objHandle = 0;
    Pkcs11_Object* pObject = NULL;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_UTF8CHAR label[MAX_ID_BYTE_SIZE] = {0};
    CK_OBJECT_HANDLE handles[3] = {0, 0, 0};
    ubyte privFound = 0;
    ubyte pubFound = 0;
    ubyte secFound = 0;
    CK_ATTRIBUTE attrTemplate[] = {
        {CKA_ID, &label, sizeof(label)-1}
    };
    CK_ATTRIBUTE dataAttrTemplate[] =
    {
        {CKA_CLASS, &dataClass, sizeof(dataClass)},
        {CKA_LABEL, label, sizeof(label)-1}
    };
    CK_ATTRIBUTE classTemplate = {CKA_CLASS, &dataClass, sizeof(dataClass)};
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if ((NULL == pGemModule) || (NULL == pGemToken) || (0 == pGemToken->tokenSession) || (NULL == objectId.pBuffer))
    {
        DB_PRINT("%s.%d: NULL Pointer on input\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }

    if (0 == objectId.bufferLen  || objectId.bufferLen > (MAX_ID_BYTE_SIZE - 1))
    {
        DB_PRINT("%s.%d: Input ID buffer size invalid.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    rVal = (CK_RV) DIGI_MEMCPY((ubyte *) label, objectId.pBuffer, objectId.bufferLen);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Internal Error.\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    attrTemplate[0].ulValueLen = objectId.bufferLen;
    dataAttrTemplate[1].ulValueLen = objectId.bufferLen;

    /* First Find if objectId is a data object */
    rVal = CALL_PKCS11_API(C_FindObjectsInit, pGemToken->tokenSession, dataAttrTemplate, 2);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjectsInit\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_FindObjects, pGemToken->tokenSession, &objHandle, 1, &objFound);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjects\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    if (0 == objHandle)
    {
        rVal = CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);
        if (CKR_OK != rVal)
        {
            DB_PRINT("%s.%d: Failed in C_FindObjectsFinal\n",__FUNCTION__, __LINE__);
            goto exit;
        }

        /*Find by objectid if a public/private/secret/certificate object */
        rVal = CALL_PKCS11_API(C_FindObjectsInit, pGemToken->tokenSession, attrTemplate, 1);
        if (CKR_OK != rVal)
        {
            DB_PRINT("%s.%d: Failed in C_FindObjectsInit\n",__FUNCTION__, __LINE__);
            goto exit;
        }

        /* For asymmetric keys there should be two objects found, a public and private handle
         * with the same CKA_ID value, there may also be a certificate object with the same ID */
        rVal = CALL_PKCS11_API(C_FindObjects, pGemToken->tokenSession, handles, 3, &objFound);
        if ((CKR_OK == rVal)  && (objFound))
        {
            rVal = (CK_RV) DIGI_CALLOC((void **) &pObject, 1, sizeof(Pkcs11_Object));
            if (CKR_OK != rVal)
            {
                DB_PRINT("%s.%d: Failed to allocate object, DIGI_CALLOC\n",__FUNCTION__, __LINE__);
                goto exit;
            }
            
            pObject->refCount = 1;
            pObject->prvObject = 0;
            pObject->pubObject = 0;

            for (i = 0; i < objFound; i++)
            {
                /* Check the class type of the object */
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, handles[i], &classTemplate, 1);
                if (CKR_OK != rVal)
                {
                    DB_PRINT("%s.%d: Failed in C_GetAttributeValue\n",__FUNCTION__, __LINE__);
                    goto exit;
                }

                /* Set the handle in the new object */
                switch(dataClass)
                {
                    case CKO_PRIVATE_KEY:
                        /* We cant have two keys of the same type with the same ID */
                        if (TRUE == privFound)
                        {
                            if (NULL != pObject->objectId.pBuffer)
                            {
                                (void) DIGI_MEMSET_FREE(&pObject->objectId.pBuffer, pObject->objectId.bufferLen);
                                pObject->objectId.bufferLen = 0;
                            }
                            (void) DIGI_FREE((void **)&pObject);
                            DB_PRINT(
                                "%s.%d: More than two objects with the same CKA_ID have been found. \
                                Please use PKCS11 key management utilities to restore key id consistency.\n",
                                __FUNCTION__, __LINE__);
                            goto exit;
                        }
                        else
                        {
                            privFound = TRUE;
                        }
                        pObject->prvObject = handles[i];
                        if (NULL == pObject->objectId.pBuffer)
                        {               
                            rVal = (CK_RV) TAP_UTILS_copyBuffer(&pObject->objectId, &objectId);
                            if (CKR_OK != rVal)
                            {
                                DB_PRINT("%s.%d: Failed to copy id buffer.\n",__FUNCTION__, __LINE__);
                                goto exit;
                            }
                        }
                        pObject->pNext = NULL;
                        break;

                    case CKO_PUBLIC_KEY:
                        /* We cant have two keys of the same type with the same ID */
                        if (TRUE == pubFound)
                        {
                            if (NULL != pObject->objectId.pBuffer)
                            {
                                (void) DIGI_MEMSET_FREE(&pObject->objectId.pBuffer, pObject->objectId.bufferLen);
                                pObject->objectId.bufferLen = 0;
                            }
                            (void) DIGI_FREE((void **)&pObject);
                            DB_PRINT(
                                "%s.%d: More than two objects with the same CKA_ID have been found. \
                                Please use PKCS11 key management utilities to restore key id consistency.\n",
                                __FUNCTION__, __LINE__);
                            goto exit;
                        }
                        else
                        {
                            pubFound = TRUE;
                        }
                        pObject->pubObject = handles[i];
                        if (NULL == pObject->objectId.pBuffer)
                        {               
                            rVal = (CK_RV) TAP_UTILS_copyBuffer(&pObject->objectId, &objectId);
                            if (CKR_OK != rVal)
                            {
                                DB_PRINT("%s.%d: Failed to copy id buffer.\n",__FUNCTION__, __LINE__);
                                goto exit;
                            }
                        }
                        pObject->pNext = NULL;
                        break;
                    
                    case CKO_SECRET_KEY:
                        /* We cant have two keys of the same type with the same ID */
                        if (TRUE == secFound)
                        {
                            if (NULL != pObject->objectId.pBuffer)
                            {
                                (void) DIGI_MEMSET_FREE(&pObject->objectId.pBuffer, pObject->objectId.bufferLen);
                                pObject->objectId.bufferLen = 0;
                            }
                            (void) DIGI_FREE((void **)&pObject);
                            DB_PRINT(
                                "%s.%d: More than two objects with the same CKA_ID have been found. \
                                Please use PKCS11 key management utilities to restore key id consistency.\n",
                                __FUNCTION__, __LINE__);
                            goto exit;
                        }
                        else
                        {
                            secFound = TRUE;
                        }
                        pObject->pubObject = handles[i];
                        pObject->prvObject = handles[i];
                        if (NULL == pObject->objectId.pBuffer)
                        {               
                            rVal = (CK_RV) TAP_UTILS_copyBuffer(&pObject->objectId, &objectId);
                            if (CKR_OK != rVal)
                            {
                                DB_PRINT("%s.%d: Failed to copy id buffer.\n",__FUNCTION__, __LINE__);
                                goto exit;
                            }
                        }
                        pObject->pNext = NULL;
                        break;
                    
                    /* Do nothing for other objects */
                    case CKO_DATA:
                    case CKO_CERTIFICATE:
                    case CKO_DOMAIN_PARAMETERS:
                        break;
                        
                    default:
                        goto exit;
                }
            }
        }
        else
        {
            /* No objects found */
        }
    }
    else
    {
        /* Data object */
        pObject = MALLOC(sizeof(Pkcs11_Object));
        if (NULL == pObject)
        {
            goto exit;
        }

        pObject->refCount = 1;
        pObject->pubObject = objHandle;
        pObject->prvObject = objHandle;
        rVal = (CK_RV) TAP_UTILS_copyBuffer(&pObject->objectId, &objectId);
        if (CKR_OK != rVal)
        {
            DB_PRINT("%s.%d: Failed to copy id buffer.\n",__FUNCTION__, __LINE__);
            goto exit;
        }
        pObject->pNext = NULL;
    }

exit:

    /* NOTE: For now this method will be used to only find keys, not certificates etc...
             Free the object and return NULL if only a certificate etc... was found */
    if (NULL != pObject && 0 == pObject->prvObject && 0 == pObject->pubObject)
    {
        /* defensive code, check the buffer just in case */
        if (NULL != pObject->objectId.pBuffer)
        {
            (void) DIGI_MEMSET_FREE(&pObject->objectId.pBuffer, pObject->objectId.bufferLen);
            pObject->objectId.bufferLen = 0;
        }
        (void) DIGI_FREE((void **)&pObject);
    }

    rVal = CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjectsFinal\n",__FUNCTION__, __LINE__);
    }

null_exit:

    return pObject;
}


/* Token ID to User PIN mapping */
ubyte4 PKCS11_tokenToPin(
        TAP_TokenId tokenId
)
{
    ubyte4 pin;

    switch(tokenId)
    {
        case TOKEN_0:
            pin = PIN_LABEL_1;
            break;

        case TOKEN_1:
            pin = PIN_LABEL_3;
            break;

        case TOKEN_2:
            pin = PIN_LABEL_4;
            break;

        case TOKEN_3:
            pin = PIN_LABEL_5;
            break;

        case TOKEN_4:
            pin = PIN_LABEL_6;
            break;

        case TOKEN_5:
            pin = PIN_LABEL_7;
            break;

        default:
            pin = -1;
    }

    return pin;
}


/* Callback function for C_GenerateKeyPair(), will only be used in case of Headless */
CK_RV PKCS11_notificationCallback(
        CK_SESSION_HANDLE hSession,
        CK_NOTIFICATION event,
        CK_VOID_PTR pApplication
)
{
    ubyte4 pin = 0;
    int ret = CKR_OK;
    PIN_ROLES* role = NULL;
    CK_BYTE* pinAuth = NULL;
    Pkcs11_Module* pGemModule = NULL;
    Pkcs11_Token* pToken = NULL;

    if (0 == hSession)
    {
        ret = CKR_ARGUMENTS_BAD;
        goto exit;
    }

    pToken = PKCS11_findToken(hSession);
    if (NULL == pToken)
    {
        pGemModule = PKCS11_findModule(hSession);
        if (NULL == pGemModule)
        {
            ret = CKR_ARGUMENTS_BAD;
            goto exit;
        }
    }

    switch(event)
    {
        case CKN_INPUT_PIN:
            role = (PIN_ROLES *)pApplication;
            if (pToken)
                pin = PKCS11_tokenToPin(pToken->tokenId);
            else if (pGemModule)
                pin = PKCS11_tokenToPin(pGemModule->provisionTokenId);

            switch(pin)
            {
                case PIN_USER:
                    *role = PIN_USER;
                    break;
                case PIN_LABEL_3:
                    *role = PIN_3;
                    break;
                case PIN_LABEL_4:
                    *role = PIN_4;
                    break;
                case PIN_LABEL_5:
                    *role = PIN_5;
                    break;
                case PIN_LABEL_6:
                    *role = PIN_6;
                    break;
                case PIN_LABEL_7:
                    *role = PIN_7;
                    break;
                default:
                    ret = CKR_ARGUMENTS_BAD;
            }
            break;

        case CKN_PIN_AUTH:
            if ((NULL != pToken) && (NULL != pToken->credential.pBuffer) && (0 < pToken->credential.bufferLen))
            {
                pinAuth = (CK_BYTE *)pApplication;
                ret = (CK_RV) DIGI_MEMSET(pinAuth, 0, pToken->credential.bufferLen + 1);
                if (ret < 0)
                {
                    ret = CKR_ARGUMENTS_BAD;
                    goto exit;
                }
                /* we know pInAuth and pToken->credential.pBuffer are not NULL at this point, ignore next return code */
                (void) DIGI_MEMCPY(pinAuth, pToken->credential.pBuffer, pToken->credential.bufferLen);
            }
            else
            {
                ret = CKR_FUNCTION_NOT_SUPPORTED;
            }
            break;

        case CKN_SURRENDER:
            ret = CKR_FUNCTION_NOT_SUPPORTED;
            break;

        default:
            ret = CKR_FUNCTION_NOT_SUPPORTED;
            break;
    }

exit:
    return ret;
}

/* Check the Attribute exists or not in the list for the Attribute Value passed */
byteBoolean PKCS11_attrCheck(
        TAP_ModuleCapabilityAttributes *pGemModuleAttributes,
        TAP_ATTR_TYPE attrType,
        void* attrValue
)
{
    ubyte4 i = 0;
    int ret = 0;
    byteBoolean bResult = 0;
    ubyte* pByteValue;
    CK_VERSION* firmware;

    if ((NULL == pGemModuleAttributes) || (!attrValue))
    {
        goto exit;
    }

    for(i=0; i<pGemModuleAttributes->listLen; i++)
    {
        if (pGemModuleAttributes->pAttributeList[i].type == attrType)
        {
            switch (attrType)
            {
                case TAP_ATTR_NONE:
                    break;

                case TAP_ATTR_FIRMWARE_VERSION:
                    pByteValue = (ubyte *)pGemModuleAttributes->pAttributeList[i].pStructOfType;
                    firmware = (CK_VERSION *)attrValue;
                    if ((firmware->major == pByteValue[0]) && (firmware->minor == pByteValue[1]))
                        bResult = 1;
                    break;

                case TAP_ATTR_TAP_PROVIDER:
                    ret = DIGI_STRCMP((const sbyte *)pGemModuleAttributes->pAttributeList[i].pStructOfType, (const sbyte *)attrValue);
                    if (0 == ret)
                        bResult = 1;
                    break;

                default:
                    break;
            }
        }
    }

exit:

    return bResult;
}

/* Check the supported algorithm for the SlotId */
MSTATUS PKCS11_supportedAlgorithm(
        Pkcs11_ModuleList *pModuleList,
        ubyte* structType,
        CK_SLOT_ID slotId,
        ubyte4* algoCount
)
{
    ubyte4 i = 0;
    ubyte4 mechCount = 0;
    CK_MECHANISM_INFO mechInfo;
    CK_RV rVal = CKR_OK;
    MSTATUS status = OK;
    const ubyte4 supportedMech[]={CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN};

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pModuleList->pFuncTable;  /* caller responsible for pModuleList not null */
    if (NULL == pFuncTable)
    {
        PKCS11_FillError(NULL, &status, ERR_INTERNAL_ERROR, "ERR_INTERNAL_ERROR");
        goto exit;
    }
#endif

    if (!algoCount)
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    *algoCount = 0;

    mechCount = sizeof(supportedMech)/sizeof(ubyte4);
    for (i=0; i<mechCount; i++ )
    {
        rVal = CALL_PKCS11_API(C_GetMechanismInfo, slotId, supportedMech[i], &mechInfo);
        /* Even though EC Pair is given as unsupported but it is supported by Pkcs11 */
        if ((CKR_OK == rVal) || (CKM_EC_KEY_PAIR_GEN == supportedMech[i]))
        {
            switch(supportedMech[i])
            {
                case CKM_RSA_PKCS_KEY_PAIR_GEN:
                    if (structType)
                        structType[*algoCount] = TAP_KEY_ALGORITHM_RSA;
                    (*algoCount)++;
                    break;
                case CKM_EC_KEY_PAIR_GEN:
                    if (structType)
                        structType[*algoCount] = TAP_KEY_ALGORITHM_ECC;
                    (*algoCount)++;
                    break;
                case CKM_DSA_KEY_PAIR_GEN:
                    if (structType)
                        structType[*algoCount] = TAP_KEY_ALGORITHM_DSA;
                    (*algoCount)++;
                    break;
            }
        }
    }

exit:
    return status;
}

/* Get the supported attributes count */
ubyte4 PKCS11_supportedAttributesCount(
        TAP_ModuleCapabilityAttributes *pGemModuleAttributes
)
{
    ubyte4 i = 0;
    ubyte4 AttrCount = 0;

    if (NULL == pGemModuleAttributes)
        goto exit;

    for (i=0; i<pGemModuleAttributes->listLen; i++)
    {
        switch (pGemModuleAttributes->pAttributeList[i].type)
        {
            case TAP_ATTR_FIRMWARE_VERSION:
                AttrCount++;
                break;
            case TAP_ATTR_TOKEN_TYPE:
                AttrCount++;
                break;
            case TAP_ATTR_TAP_PROVIDER:
                AttrCount++;
                break;
            case TAP_ATTR_KEY_ALGORITHM:
                AttrCount++;
                break;
            case TAP_ATTR_GET_MODULE_CREDENTIALS:
                AttrCount++;
                break;
            case TAP_ATTR_MODULE_PROVISION_STATE:
                AttrCount++;
                break;
        }
    }

exit:
    return AttrCount;

}

/* Check Attributes Type */
byteBoolean PKCS11_checkAttributesType(
        TAP_ModuleCapabilityAttributes *pGemModuleAttributes,
        TAP_ATTR_TYPE type
)
{
    ubyte4 i = 0;
    byteBoolean bResult = FALSE;

    if (NULL == pGemModuleAttributes)
        goto exit;

    for (i=0; i<pGemModuleAttributes->listLen; i++)
    {
        if (type == pGemModuleAttributes->pAttributeList[i].type)
        {
            bResult = TRUE;
            break;
        }
    }

exit:
    return bResult;

}

/* Fetch Key Size from the Attributes passed */
ubyte4 PKCS11_fetchKeyAttrlength(
        TAP_KeyAttributes *pKeyAttributes,
        TAP_ATTR_TYPE type
)
{
    ubyte4 i = 0;
    ubyte4 keyAttrLen = 0;

    if (NULL == pKeyAttributes)
        goto exit;

    for (i=0; i<= pKeyAttributes->listLen; i++)
    {
      if (type == pKeyAttributes->pAttributeList[i].type)
        {
            keyAttrLen = pKeyAttributes->pAttributeList[i].length;
            break;
        }

    }

exit:
    return keyAttrLen;

}


void PKCS11_FillError(
        TAP_Error* error,
        MSTATUS* pStatus,
        MSTATUS statusVal,
        const char* pErrString
)
{

    if (pStatus)
        *pStatus = statusVal;

    if (NULL == error)
        goto exit;

    error->tapError = statusVal;
    if (NULL == error->tapErrorString.pBuffer)
    {
        goto exit;
    }

    strncpy((char *)error->tapErrorString.pBuffer, pErrString, MAX_ERROR_BUFFER - 1);
    ((char *)error->tapErrorString.pBuffer)[MAX_ERROR_BUFFER - 1] = '\0';
    error->tapErrorString.bufferLen = strlen(pErrString);

exit:
    return;

}

/* Converts pkcs11 error to NanoSMP error */
MSTATUS PKCS11_nanosmpErr(
        Pkcs11_Module* pGemModule,
        CK_RV rVal
)
{
    MSTATUS status = OK;

    DB_PRINT("PKCS11 error, rv: %d\n", rVal);
    switch (rVal)
    {
        case CKR_OK:
            status = OK;
            break;

        case CKR_HOST_MEMORY:
            status = ERR_MEM_;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_, "CKR_HOST_MEMORY");
            break;

        case CKR_SLOT_ID_INVALID:
            status = ERR_ID;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_ID, "CKR_SLOT_ID_INVALID");
            break;

        case CKR_DATA_INVALID:
            status = ERR_UNKNOWN_DATA;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_UNKNOWN_DATA, "CKR_DATA_INVALID");
            break;

        case CKR_DATA_LEN_RANGE:
            status = ERR_UNSUPPORTED_SIZE;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_UNSUPPORTED_SIZE, "CKR_DATA_LEN_RANGE");
            break;

        case CKR_FUNCTION_NOT_SUPPORTED:
            status = ERR_SMP_UNSUPPORTED_FUNCTIONALITY;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_SMP_UNSUPPORTED_FUNCTIONALITY, "CKR_FUNCTION_NOT_SUPPORTED");
            break;

        case CKR_OBJECT_HANDLE_INVALID:
            status = ERR_TAP_INVALID_HANDLE;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_TAP_INVALID_HANDLE, "CKR_OBJECT_HANDLE_INVALID");
            break;

        case CKR_SIGNATURE_INVALID:
            status = ERR_TAP_INVALID_SIGNATURE;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_TAP_INVALID_SIGNATURE, "CKR_SIGNATURE_INVALID");
            break;

        case CKR_RANDOM_NO_RNG:
            status = ERR_TAP_GET_RANDOM_NUM_FAILED;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_TAP_GET_RANDOM_NUM_FAILED, "CKR_RANDOM_NO_RNG");
            break;

        case CKR_BUFFER_TOO_SMALL:
            status = ERR_BUFFER_TOO_SMALL;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_BUFFER_TOO_SMALL, "CKR_BUFFER_TOO_SMALL");
            break;

        case CKR_ARGUMENTS_BAD:
        case CKR_DOMAIN_PARAMS_INVALID:
            status = ERR_INVALID_ARG;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "CKR_ARGUMENTS_BAD");
            break;

        case CKR_CRYPTOKI_NOT_INITIALIZED:
        case CKR_CRYPTOKI_ALREADY_INITIALIZED:
            status = ERR_CRYPTO;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_CRYPTO, "CKR_CRYPTOKI_NOT_INITIALIZED");
            break;

        case CKR_SESSION_EXISTS:
        case CKR_SESSION_READ_ONLY:
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
        case CKR_SESSION_READ_ONLY_EXISTS:
        case CKR_SESSION_READ_WRITE_SO_EXISTS:
            status = ERR_SESSION;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_SESSION, "CKR_SESSION_EXISTS");
            break;

        case CKR_KEY_HANDLE_INVALID:
        case CKR_KEY_SIZE_RANGE:
        case CKR_KEY_TYPE_INCONSISTENT:
        case CKR_KEY_NOT_NEEDED:
        case CKR_KEY_CHANGED:
        case CKR_KEY_INDIGESTIBLE:
            status = ERR_KEY;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_KEY, "CKR_KEY_HANDLE_INVALID");
            break;

        case CKR_PIN_INVALID:
            status = ERR_GENERAL;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_GENERAL, "CKR_PIN_INVALID");
            break;

        case CKR_PIN_INCORRECT:
            status = ERR_GENERAL;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_GENERAL, "CKR_PIN_INCORRECT");
            break;

        case CKR_DEVICE_MEMORY:
            status = ERR_GENERAL;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_GENERAL, "CKR_DEVICE_MEMORY");
            break;

        case CKR_GENERAL_ERROR:
        case CKR_MUTEX_BAD:
        case CKR_MUTEX_NOT_LOCKED:
        case CKR_RANDOM_SEED_NOT_SUPPORTED:
        case CKR_NEED_TO_CREATE_THREADS:
        case CKR_KEY_NEEDED:
        case CKR_ATTRIBUTE_VALUE_INVALID:
        case CKR_ATTRIBUTE_TYPE_INVALID:
        case CKR_ATTRIBUTE_READ_ONLY:
        case CKR_DEVICE_ERROR:
        case CKR_DEVICE_REMOVED:
        case CKR_ENCRYPTED_DATA_INVALID:
        case CKR_ENCRYPTED_DATA_LEN_RANGE:
        case CKR_FUNCTION_CANCELED:
        case CKR_FUNCTION_NOT_PARALLEL:
        case CKR_OPERATION_ACTIVE:
        case CKR_OPERATION_NOT_INITIALIZED:
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
        case CKR_UNWRAPPING_KEY_SIZE_RANGE:
        case CKR_PIN_EXPIRED:
        case CKR_PIN_LEN_RANGE:
        case CKR_MECHANISM_PARAM_INVALID:
        case CKR_MECHANISM_INVALID:
        case CKR_KEY_UNEXTRACTABLE:
        case CKR_KEY_NOT_WRAPPABLE:
        case CKR_KEY_FUNCTION_NOT_PERMITTED:
        case CKR_PIN_LOCKED:
        case CKR_SESSION_CLOSED:
        case CKR_SESSION_COUNT:
        case CKR_SESSION_HANDLE_INVALID:
        case CKR_SIGNATURE_LEN_RANGE:
        case CKR_TEMPLATE_INCOMPLETE:
        case CKR_TEMPLATE_INCONSISTENT:
        case CKR_TOKEN_NOT_PRESENT:
        case CKR_TOKEN_NOT_RECOGNIZED:
        case CKR_TOKEN_WRITE_PROTECTED:
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
        case CKR_SAVED_STATE_INVALID:
        case CKR_ATTRIBUTE_SENSITIVE:
        case CKR_FUNCTION_FAILED:
        case CKR_CANCEL:
        case CKR_NO_EVENT:
        case CKR_CANT_LOCK:
        case CKR_INFORMATION_SENSITIVE:
        case CKR_STATE_UNSAVEABLE:
        case CKR_FUNCTION_REJECTED:
            status = ERR_GENERAL;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_GENERAL, "CKR_GENERAL_ERROR");
            break;

        default:
            status = ERR_INTERNAL_ERROR;
            if (pGemModule)
                PKCS11_FillError(&pGemModule->error, &status, ERR_INTERNAL_ERROR, "UNKNOWN ERROR");
            break;
    }

    return status;
}

MSTATUS PKCS11_createKeyLabelAlloc(
    const sbyte *pPrefix,
    const sbyte *pKeyClass,
    TAP_KEY_ALGORITHM keyAlgorithm,
    TAP_RAW_KEY_SIZE keySize,
    TAP_ECC_CURVE eccCurve,
    TAP_Buffer objId,
    sbyte **ppLabel
)
{
    MSTATUS status = OK;
    sbyte *pBuffer = NULL;
    sbyte *pIter = NULL;
    ubyte4 bufferLen = 0;
    sbyte pObjIdBuf[2*MAX_ID_BYTE_SIZE + 2] = {0};
    ubyte4 objIdStrLen = 0;
    sbyte *pKeyAlgoStr = NULL;
    sbyte keySizeStrSpace[12] = {0}; /* big enough for a ubyte4 */
    sbyte *pKeySizeStr = NULL;
    ubyte4 prefixLen = 0;
    ubyte4 classLen = 0;
    ubyte4 keyAlgoLen = 3;
    ubyte4 keySizeLen = 4;
    ubyte4 i = 0;

    for (i = 0; i < objId.bufferLen; i++)
    {
        pObjIdBuf[2*i] = (sbyte) returnHexDigit( (objId.pBuffer[i] >> 4) & 0x0f);
        pObjIdBuf[2*i + 1] = (sbyte) returnHexDigit( objId.pBuffer[i] & 0x0f); 
    }

    objIdStrLen = DIGI_STRLEN((sbyte*)pObjIdBuf);
    prefixLen = DIGI_STRLEN(pPrefix);
    classLen = DIGI_STRLEN(pKeyClass);

    status = ERR_INVALID_INPUT;
    switch(keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            {
                switch (keySize)
                {
                    case TAP_KEY_SIZE_1024:
                        pKeySizeStr = (sbyte *) "1024";
                        break;

                    case TAP_KEY_SIZE_UNDEFINED:
                    case TAP_KEY_SIZE_2048:
                        pKeySizeStr = (sbyte *) "2048";
                        break;

                    case TAP_KEY_SIZE_3072:
                        pKeySizeStr = (sbyte *) "3072";
                        break;

                    case TAP_KEY_SIZE_4096:
                        pKeySizeStr = (sbyte *) "4096";
                        break;
                    default:
                        goto exit;
                }

            }
            pKeyAlgoStr = (sbyte *) "RSA";
            break;
        case TAP_KEY_ALGORITHM_ECC:
            {
                switch (eccCurve)
                {
                    case TAP_ECC_CURVE_NIST_P192:
                        pKeySizeStr = (sbyte *) "P192";
                        break;

                    case TAP_ECC_CURVE_NIST_P224:
                        pKeySizeStr = (sbyte *) "P224";
                        break;

                    case TAP_ECC_CURVE_NIST_P256:
                        pKeySizeStr = (sbyte *) "P256";
                        break;

                    case TAP_ECC_CURVE_NIST_P384:
                        pKeySizeStr = (sbyte *) "P384";
                        break;

                    case TAP_ECC_CURVE_NIST_P521:
                        pKeySizeStr = (sbyte *) "P521";
                        break;
                    default:
                        goto exit;
                }

            }
            pKeyAlgoStr = (sbyte *) "ECC";
            break;
        case TAP_KEY_ALGORITHM_AES:
            {
                keySizeLen = 3;
                switch (keySize)
                {
                    case TAP_KEY_SIZE_UNDEFINED:
                        pKeySizeStr = (sbyte *) "000";
                        break;

                    case TAP_KEY_SIZE_128:
                        pKeySizeStr = (sbyte *) "128";
                        break;

                    case TAP_KEY_SIZE_192:
                        pKeySizeStr = (sbyte *) "192";
                        break;

                    case TAP_KEY_SIZE_256:
                        pKeySizeStr = (sbyte *) "256";
                        break;
                    default:
                        goto exit;
                }
            }
            pKeyAlgoStr = (sbyte *) "AES";
            break;
        case TAP_KEY_ALGORITHM_DES:
            keySizeLen = 0;
            pKeyAlgoStr = (sbyte *) "DES";
            break;
        case TAP_KEY_ALGORITHM_TDES:
            keySizeLen = 0;
            pKeyAlgoStr = (sbyte *) "TDES";
            keyAlgoLen = 4;
            break;
        case TAP_KEY_ALGORITHM_HMAC:
            pKeySizeStr = (sbyte *) &keySizeStrSpace;
            (void) sprintf((char *) pKeySizeStr, "%d", keySize);
            keySizeLen = DIGI_STRLEN(pKeySizeStr);
            pKeyAlgoStr = (sbyte *) "HMAC";
            keyAlgoLen = 4;
            break;
    }

    /* Allocate enough space for the following:
     * ( prefix-class-algo-size-id || 0) */
    bufferLen = prefixLen + 1 + classLen + 1 + keyAlgoLen + 1 + keySizeLen + 1 + objIdStrLen + 1;
    status = DIGI_CALLOC((void **)&pBuffer, bufferLen, 1);
    if (OK != status)
        goto exit;

    /* Copy in prefix */
    pIter = pBuffer;
    status = DIGI_MEMCPY (
        (void *)pIter, (const void *)pPrefix, prefixLen);
    if (OK != status)
        goto exit;

    pIter += prefixLen;

    if (classLen)
    {
        /* Copy in key class, ie pub/priv */
        status = DIGI_MEMCPY((void *)pIter, (const void *)"-", 1);
        if (OK != status)
            goto exit;

        pIter += 1;

        status = DIGI_MEMCPY (
            (void *)pIter, (const void *)pKeyClass, classLen);
        if (OK != status)
            goto exit;

        pIter += classLen;
    }

    /* Copy in algo, ie RSA/ECC */
    status = DIGI_MEMCPY((void *)pIter, (const void *)"-", 1);
    if (OK != status)
        goto exit;

    pIter += 1;

    status = DIGI_MEMCPY (
        (void *)pIter, (const void *)pKeyAlgoStr, keyAlgoLen);
    if (OK != status)
        goto exit;

    /* Copy in key size, represents curve for ECC */
    pIter += keyAlgoLen;

    if (keySizeLen)
    {
        status = DIGI_MEMCPY((void *)pIter, (const void *)"-", 1);
        if (OK != status)
            goto exit;

        pIter += 1;
        status = DIGI_MEMCPY (
            (void *)pIter, (const void *)pKeySizeStr, keySizeLen);
        if (OK != status)
            goto exit;

        /* Copy in object ID */
        pIter += keySizeLen;
    }

    status = DIGI_MEMCPY((void *)pIter, (const void *)"-", 1);
    if (OK != status)
        goto exit;

    pIter += 1;
    status = DIGI_MEMCPY (
        (void *)pIter, (const void *)pObjIdBuf, objIdStrLen);
    if (OK != status)
        goto exit;

    *ppLabel = pBuffer;
    pBuffer = NULL;

exit:
    if (NULL != pBuffer)
    {
        DIGI_FREE((void **)&pBuffer);
    }

    return status;
}

#ifdef __ENABLE_DIGICERT_PKCS11_SMP_TOOLS__

MSTATUS PKCS11_deleteAllKeys(
    Pkcs11_Module* pGemModule,
    Pkcs11_Token* pGemToken
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_ULONG objFound = 0;
    CK_OBJECT_HANDLE objHandle = 0;
    CK_BYTE retry = FALSE;

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pGemModule->pFuncTable;  /* caller responsible for pGemModule not null */
    if (NULL == pFuncTable)
    {
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        return ERR_INVALID_INPUT;
    }
#endif

    if ((NULL == pGemToken) || (0 == pGemToken->tokenSession))
    {
        DB_PRINT("%s.%d: NULL Pointer on input\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    DB_PRINT("PKCS11 Deleting All Keys...\n");

    do
    {
        objFound = 0;
        objHandle = 0;
        rVal = CALL_PKCS11_API(C_FindObjectsInit, pGemToken->tokenSession, NULL, 0);
        if (CKR_OK != rVal)
        {
            DB_PRINT("%s.%d: Failed in C_FindObjectsInit\n",__FUNCTION__, __LINE__);
            goto exit;
        }

        rVal = CALL_PKCS11_API(C_FindObjects, pGemToken->tokenSession, &objHandle, 1, &objFound);
        if (CKR_OK != rVal)
        {
            DB_PRINT("%s.%d: Failed in C_FindObjects\n",__FUNCTION__, __LINE__);
            goto exit;
        }

        if ( (objFound > 0) && (objHandle > 0) )
        {
            DB_PRINT("Deleting a key...\n");
            rVal = CALL_PKCS11_API(C_DestroyObject, pGemToken->tokenSession, objHandle);
            if (CKR_OK != rVal)
            {
                if (TRUE == retry)
                {
                    DB_PRINT("%s.%d: Failed in C_DestroyObject\n",__FUNCTION__, __LINE__);
                    /*goto exit;*/
                }

                retry = TRUE;
            }
            else
            {
                retry = FALSE;
            }
        }
        else
        {
            retry = FALSE;
        }

        rVal = CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);
        if (CKR_OK != rVal)
        {
            DB_PRINT("%s.%d: Failed in C_FindObjectsFinal\n",__FUNCTION__, __LINE__);
        }
    } while(objFound != 0);

exit:

    if (CKR_OK != rVal)
    {
        CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);
    }

    if (CKR_OK == rVal)
    {
        return OK;
    }

    return ERR_GENERAL;
}

MSTATUS PKCS11_listModuleIdStrings(
    ubyte *pLibPath
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_SLOT_ID_PTR pSlotList = NULL;
    CK_ULONG count = 0;
    CK_TOKEN_INFO slotInfo = {0};
    int i=0,j=0;
    ubyte serialNumber[SHA256_HASH_LENGTH];

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    void *pLib = NULL;
    CK_RV (*funcPtr)(CK_FUNCTION_LIST_PTR_PTR);
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;

    if (NULL == pLibPath)
    {
        status = ERR_NULL_POINTER;
        goto null_exit;
    }
    
    status = DIGICERT_loadDynamicLibraryEx((const char *) pLibPath, &pLib);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Unable to open PKCS11 Library: %s status = %d\n",__FUNCTION__, __LINE__, pLibPath, status);
        goto null_exit;
    }

    status = DIGICERT_getSymbolFromLibrary("C_GetFunctionList", pLib, (void **) &funcPtr);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Unable to find method C_GetFunctionList in PKCS11 Library: %s status = %d\n",
                 __FUNCTION__, __LINE__, pLibPath, status);
        goto null_exit;
    }

    rVal = funcPtr(&pFuncTable);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        DB_PRINT("%s.%d: Error retrieving function pointer table in PKCS11 Library: %s status = %d\n",
                __FUNCTION__, __LINE__, pLibPath, status);
        goto null_exit;
    }
#else 
    MOC_UNUSED(pLibPath);
#endif

    /* call initialize */
    rVal = CALL_PKCS11_API(C_Initialize, NULL_PTR);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        goto exit;
    }

    /* Get number of slots in system */
    rVal = CALL_PKCS11_API(C_GetSlotList, CK_TRUE, NULL_PTR, &count);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        DB_PRINT("%s.%d Failed to get slot list. status=%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (OK != (status = DIGI_MALLOC((void**)&pSlotList, count * sizeof(CK_SLOT_ID))))
    {
        DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Now Get the complete slot list */
    rVal = CALL_PKCS11_API(C_GetSlotList, CK_TRUE, pSlotList, &count);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        DB_PRINT("%s.%d Failed to get slot list. status=%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (0 == count)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d No slots in the module. status=%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    if (OK != (status = DIGI_MEMSET((ubyte*)&slotInfo, 0, sizeof(CK_TOKEN_INFO))))
    {
        DB_PRINT("%s.%d Failed in MEMSET. status=%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    for (i=0; i<count; i++)
    {
        rVal = CALL_PKCS11_API(C_GetTokenInfo, pSlotList[i], &slotInfo);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(NULL, rVal);
            DB_PRINT("%s.%d Failed to get slotinfo. status=%d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK != (status = CRYPTO_INTERFACE_SHA256_completeDigest(slotInfo.serialNumber, PKCS11_SERIAL_NO_BUF_LEN, serialNumber)))
#else
        if (OK != (status = SHA256_completeDigest(slotInfo.serialNumber, PKCS11_SERIAL_NO_BUF_LEN, serialNumber)))
#endif
        {
            DB_PRINT("%s.%d Failed to copy buffer. status=%d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        printf("Slot[%d] Module Id String: ", i);
        for (j = 0; j < 32; j++)
        {
            printf("%02x", serialNumber[j]);
        }
        printf("\n");
    }

exit:

    if (NULL != pSlotList)
        (void) DIGI_FREE((void**)&pSlotList);
    
    (void) CALL_PKCS11_API(C_Finalize, NULL_PTR);

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
null_exit:

    if (NULL != pLib)
    {
        (void) DIGICERT_unloadDynamicLibrary(pLib);
    }
#endif

    return status;
}

MSTATUS PKCS11_printSlotDescriptions(
    ubyte *pLibPath
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;

    ubyte4 i = 0;
    CK_SLOT_ID_PTR pSlotList = NULL;
    CK_ULONG count = 0;
    CK_SLOT_INFO slotInfo;
    CK_CHAR slotDesc[MAX_SLOT_DESC_SZ];

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    void *pLib = NULL;
    CK_RV (*funcPtr)(CK_FUNCTION_LIST_PTR_PTR);
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;

    if (NULL == pLibPath)
    {
        status = ERR_NULL_POINTER;
        goto null_exit;
    }

    status = DIGICERT_loadDynamicLibraryEx((const char *) pLibPath, &pLib);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Unable to open PKCS11 Library: %s status = %d\n",__FUNCTION__, __LINE__, pLibPath, status);
        goto null_exit;
    }

    status = DIGICERT_getSymbolFromLibrary("C_GetFunctionList", pLib, (void **) &funcPtr);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Unable to find method C_GetFunctionList in PKCS11 Library: %s status = %d\n",
                 __FUNCTION__, __LINE__, pLibPath);
        goto null_exit;
    }

    rVal = funcPtr(&pFuncTable);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        DB_PRINT("%s.%d: Error retrieving function pointer table in PKCS11 Library: %s status = %d\n",
                __FUNCTION__, __LINE__, pLibPath, status);
        goto null_exit;
    }
#else 
    MOC_UNUSED(pLibPath);
#endif

    /* call initialize */
    rVal = CALL_PKCS11_API(C_Initialize, NULL_PTR);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        goto exit;
    }

    /* Get the number of slots */
    rVal = CALL_PKCS11_API(C_GetSlotList, CK_TRUE, NULL_PTR, &count);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        goto exit;
    }

    pSlotList = (CK_SLOT_ID_PTR)MALLOC(count * sizeof(CK_SLOT_ID));
    if (NULL == pSlotList)
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    /* Now Get the complete slot list */
    rVal = CALL_PKCS11_API(C_GetSlotList, CK_TRUE, pSlotList, &count);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        goto exit;
    }

    if (0 == count)
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    /* Fetch the main slots in the system and display the slot description */
    for (i=0; i<count; i++)
    {
        DIGI_MEMSET((ubyte*)&slotInfo, 0, sizeof(CK_SLOT_INFO));
        rVal = CALL_PKCS11_API(C_GetSlotInfo, pSlotList[i], &slotInfo);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(NULL, rVal);
            goto exit;
        }

        DIGI_MEMSET((ubyte*)slotDesc, 0, MAX_SLOT_DESC_SZ);
        status = PKCS11_copySlotDesc(slotDesc, slotInfo.slotDescription, MAX_SLOT_DESC_SZ - 1);
        if (OK != status)
        {
            goto exit;
        }

        printf("Slot[%d] description: %s\n", i, slotDesc);
    }

exit:

    (void) CALL_PKCS11_API(C_Finalize, NULL_PTR);

    if (NULL != pSlotList)
        (void) DIGI_FREE((void**)&pSlotList);

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
null_exit:

    if (NULL != pLib)
    {
        (void) DIGICERT_unloadDynamicLibrary(pLib);
    }
#endif

    return status;
}

MSTATUS PKCS11_listAllKeys(
    Pkcs11_Module *pGemModule,
    Pkcs11_Token* pGemToken
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    ubyte *p = NULL;
    CK_ULONG i;
    CK_ULONG keyId = 0;
    CK_ULONG objFound = 0;
    CK_OBJECT_HANDLE objHandle = 0;
    CK_ULONG labelLen = 0;
    CK_OBJECT_CLASS dataClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE classTemplate = {CKA_CLASS, &dataClass, sizeof(dataClass)};
    CK_ATTRIBUTE idTemplate[] =
    {
        {CKA_ID, NULL, 0}
    };
    CK_ATTRIBUTE labelTemplate[] =
    {
        {CKA_LABEL, NULL, 0}
    };

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pGemModule->pFuncTable;  /* caller responsible for pGemModule not null */
    if (NULL == pFuncTable)
    {
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        return ERR_INVALID_INPUT;
    }
#endif

    if ((NULL == pGemToken) || (0 == pGemToken->tokenSession))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d: NULL Pointer on input\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    DB_PRINT("PKCS11 Listing All Keys...\n");

    rVal = CALL_PKCS11_API(C_FindObjectsInit, pGemToken->tokenSession, NULL, 0);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjectsInit\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    do
    {
        objFound = 0;
        rVal = CALL_PKCS11_API(C_FindObjects, pGemToken->tokenSession, &objHandle, 1, &objFound);
        if (CKR_OK != rVal)
        {
            DB_PRINT("%s.%d: Failed in C_FindObjects\n",__FUNCTION__, __LINE__);
            goto exit;
        }

        /* We found an object, list some attributes */
        if (objFound > 0)
        {
            printf("Found key object:\n handle: %lu", objHandle);
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, objHandle, &classTemplate, 1);
            if (CKR_OK == rVal)
            {
                printf(" dataclass: %ld", dataClass);
            }

            /* Get the id length */
            if (NULL != idTemplate[0].pValue)
            {
                DIGI_FREE((void **)&idTemplate[0].pValue);
            }
            idTemplate[0].pValue = NULL;
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, objHandle, idTemplate, 1);
            if (CKR_OK == rVal)
            {
                /* If we got the length, allocate a buffer, retrieve the value, and print it */
                DIGI_MALLOC((void **)&idTemplate[0].pValue, idTemplate[0].ulValueLen + 1);
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, objHandle, idTemplate, 1);
                printf(" ID: ");
                if (CKR_OK == rVal)
                {
                    p = (ubyte *)idTemplate[0].pValue;
                    for (i = 0; i < idTemplate[0].ulValueLen; i++)
                    {
                        printf("%02X", p[i]);
                    }
                }
            }

            /* Now do the same for the label */
            labelLen = 0;
            if (NULL != labelTemplate[0].pValue)
            {
                DIGI_FREE((void **)&labelTemplate[0].pValue);
            }
            labelTemplate[0].pValue = NULL;
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, objHandle, labelTemplate, 1);
            if (CKR_OK == rVal)
            {
                labelLen = labelTemplate[0].ulValueLen;

                if (labelLen > 1)
                {
                    DIGI_CALLOC((void **)&labelTemplate[0].pValue, labelLen + 1, 1);

                    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, objHandle, labelTemplate, 1);
                    if (CKR_OK != rVal)
                    {
                        DB_PRINT("%s.%d: Failed in C_FindObjects\n",__FUNCTION__, __LINE__);
                        goto exit;
                    }
                    DB_PRINT(" Label: %s\n", (char *)labelTemplate[0].pValue);
                }
                else
                {
                    DB_PRINT("\n");
                }
            }
            else
            {
                DB_PRINT("\n");
            }
        }
    } while(objFound);

exit:

    DB_PRINT("Done listing keys\n");
    rVal = CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjectsFinal\n",__FUNCTION__, __LINE__);
    }

    if (NULL != idTemplate[0].pValue)
    {
        DIGI_FREE((void **)&idTemplate[0].pValue);
    }
    if (NULL != labelTemplate[0].pValue)
    {
        DIGI_FREE((void **)&labelTemplate[0].pValue);
    }

    if (CKR_OK == rVal)
    {
        return OK;
    }

    return ERR_GENERAL;
}

MSTATUS PKCS11_getCertData(
    Pkcs11_Module* pGemModule,
    Pkcs11_Token* pGemToken,
    ubyte *pCertId,
    ubyte4 certIdLen,
    ubyte **ppCertData,
    usize *pCertDataLen
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_ULONG i;
    CK_ULONG objFound = 0;
    CK_OBJECT_HANDLE objHandle = 0;
    CK_OBJECT_CLASS dataClass = CKO_CERTIFICATE;
    CK_ATTRIBUTE searchTemplate[] =
    {
        {CKA_ID, NULL, 0},
        {CKA_CLASS, &dataClass, sizeof(dataClass)}
    };
    CK_ATTRIBUTE valueTemplate[] =
    {
        {CKA_VALUE, NULL, 0}
    };

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pGemModule->pFuncTable;  /* caller responsible for pGemModule not null */
    if (NULL == pFuncTable)
    {
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        return ERR_INVALID_INPUT;
    }
#endif

    if ((NULL == pGemToken) || (0 == pGemToken->tokenSession) || (NULL == pCertId) || 
        (0 == certIdLen) || (NULL == ppCertData) || (NULL == pCertDataLen))
    {
        DB_PRINT("%s.%d: NULL Pointer on input\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    searchTemplate[0].pValue = (void *)pCertId;
    searchTemplate[0].ulValueLen = certIdLen;

    rVal = CALL_PKCS11_API(C_FindObjectsInit, pGemToken->tokenSession, searchTemplate, 2);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjectsInit\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_FindObjects, pGemToken->tokenSession, &objHandle, 1, &objFound);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjects\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    if (0 == objFound)
    {
        status = ERR_NOT_FOUND;
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjectsFinal\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, objHandle, valueTemplate, 1);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_GetAttributeValue\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    status = DIGI_MALLOC((void **)&valueTemplate[0].pValue, valueTemplate[0].ulValueLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Failed in DIGI_MALLOC\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, objHandle, valueTemplate, 1);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_GetAttributeValue\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    *ppCertData = (ubyte *)valueTemplate[0].pValue;
    *pCertDataLen = (usize)valueTemplate[0].ulValueLen;

exit:

    CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);

    if (CKR_OK == rVal)
    {
        return OK;
    }

    return status;
}

MSTATUS PKCS11_deleteById(
    Pkcs11_Module* pGemModule,
    Pkcs11_Token* pGemToken,
    ubyte *pId,
    ubyte4 idLen
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_ULONG i;
    CK_ULONG objFound = 0;
    CK_OBJECT_HANDLE objHandles[3] = {0, 0, 0};
    CK_ATTRIBUTE searchTemplate[] =
    {
        {CKA_ID, NULL, 0}
    };

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pGemModule->pFuncTable;  /* caller responsible for pGemModule not null */
    if (NULL == pFuncTable)
    {
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        return ERR_INVALID_INPUT;
    }
#endif

    if ((NULL == pGemToken) || (0 == pGemToken->tokenSession) || 
        (NULL == pId) || (0 == idLen))
    {
        DB_PRINT("%s.%d: NULL Pointer on input\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    searchTemplate[0].pValue = (void *)pId;
    searchTemplate[0].ulValueLen = idLen;

    rVal = CALL_PKCS11_API(C_FindObjectsInit, pGemToken->tokenSession, searchTemplate, 1);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjectsInit\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_FindObjects, pGemToken->tokenSession, objHandles, 3, &objFound);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjects\n",__FUNCTION__, __LINE__);
        goto exit;
    }

    if (0 == objFound)
    {
        status = ERR_NOT_FOUND;
        rVal = 1; /* so status gets returned */
        goto exit;
    }

    for (i = 0; i < objFound; i++)
    {
        if (objHandles[i] != 0)
        {
            rVal = CALL_PKCS11_API(C_DestroyObject, pGemToken->tokenSession, objHandles[i]);
            if (CKR_OK != rVal)
            {
                DB_PRINT("%s.%d: Failed in C_DestroyObject\n",__FUNCTION__, __LINE__);
                goto exit;
            }
        }
    }

    rVal = CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);
    if (CKR_OK != rVal)
    {
        DB_PRINT("%s.%d: Failed in C_FindObjectsFinal\n",__FUNCTION__, __LINE__);
        goto exit;
    }

exit:

    CALL_PKCS11_API(C_FindObjectsFinal, pGemToken->tokenSession);

    if (CKR_OK == rVal)
    {
        return OK;
    }

    return status;
}

#endif /* #ifdef __ENABLE_DIGICERT_PKCS11_SMP_TOOLS__ */

#endif /* #if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_PKCS11__)) */
