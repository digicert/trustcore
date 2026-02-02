/*
 * smp_tee_util.c
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
 * @file       smp_tee_util.c
 * @brief      utility file for smp_tee_api.c
 * @details    defines helper and utility functions required by smp_tee_api.c
 */

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TEE__))
#include "../../common/moptions.h"
#include "../../common/mfmgmt.h"
#include "../../tap/tap_utils.h"

#include "tee_client_api.h"
#include "secure_storage_ta.h"

#include "smp_tee_api.h"
#include "smp_tee.h"

/* for atoi() */
#include <stdlib.h>
/* for sprintf and printf when DB_PRINT is not defined */
#include <stdio.h>

#if !(defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__))
#define DB_PRINT(...)
#endif

/* Global Mutex for protecting Tee modules */
/* extern RTOS_MUTEX gGemMutex = NULL; */

/* We'll only have one module */
extern Tee_Module gModule;

static MSTATUS SMP_TEE_parseConf(ubyte* pBufHead);

/*
 * Init routine called from SMP_TEE_register API.
 * Allocate all necessary objects and also initialize module if config
 * file provided and initialize tee library.
 */
MOC_EXTERN MSTATUS SMP_TEE_init(
    TAP_ConfigInfo *pConfigInfo
)
{
    MSTATUS status = OK;
    ubyte *pTmpConfig = NULL;

    if (NULL == pConfigInfo || NULL == pConfigInfo->configInfo.pBuffer)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error NULL config, status = %d\n",
            __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }

    if (0 == pConfigInfo->configInfo.bufferLen)
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Error empty config, status = %d\n",
            __FUNCTION__, __LINE__, (int)status);
        goto exit;  
    }

#if 0
    if (gGemMutex)
    {
        status = ERR_GENERAL;
        DB_PRINT("%s.%d Unable to create mutex, status  = %d\n",
            __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }

    DIGI_MEMSET((ubyte*)&gGemMutex, 0x00, sizeof(RTOS_MUTEX));
    status = RTOS_mutexCreate(&gGemMutex, (enum mutexTypes) 0, 1);
#endif

    if (TAP_PROVIDER_TEE != pConfigInfo->provider)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Error Provider is not TEE, status  = %d\n",
            __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }
        
    /* We copy over the config to make sure there is a '\0' null char at end */
    status = DIGI_MALLOC((void **) &pTmpConfig, pConfigInfo->configInfo.bufferLen + 1);
    if (OK != status)
        goto exit;

    (void) DIGI_MEMCPY(pTmpConfig, pConfigInfo->configInfo.pBuffer, pConfigInfo->configInfo.bufferLen);
    pTmpConfig[pConfigInfo->configInfo.bufferLen] = '\0';

    status = SMP_TEE_parseConf(pTmpConfig);
       
exit:

    if (NULL != pTmpConfig)
    {
        (void) DIGI_FREE((void **) &pTmpConfig);
    }

    return status;
}

MOC_EXTERN MSTATUS SMP_TEE_uninit(void)
{
    MSTATUS status = OK;
    /* vars needed for ALL_SMP_API */
    TAP_ErrorAttributes *pErrorRules = NULL;
    TAP_ErrorAttributes **ppErrAttrReturned = NULL;

    /* The module should already be uninitialized and have the tokens freed, but in case not */
    if (NULL != gModule.pTokenHead)
    {
        status = CALL_SMP_API(TEE, uninitModule, (TAP_ModuleHandle) ((uintptr) &gModule));
    }

    if (NULL != gModule.pConfig)
    {
        if (NULL != gModule.pConfig->modDesc)
        {
            (void) DIGI_FREE((void **) &gModule.pConfig->modDesc);
        }
        
        (void) DIGI_MEMSET_FREE((ubyte **) &gModule.pConfig, sizeof(Tee_Config));
    }

    return status;
}

static ubyte* SMP_TEE_fetchStr(
    ubyte* pBuf,
    ubyte* pOutBuf,
    ubyte4 maxLen
)
{
    int i = 0;
    ubyte *pVal = pOutBuf;
    int size = 0;

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

static ubyte4 SMP_TEE_fetchInt(
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

static ubyte* SMP_TEE_parseString(
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

static MSTATUS SMP_TEE_parseTokenStr(ubyte *pTokenStr, Tee_Config *pConf)
{
    MSTATUS status = OK;
    ubyte *pIntStart = pTokenStr;
    ubyte4 index = 0;

    if (NULL == pTokenStr || 0 == *pTokenStr) /* internal method, pConf can't be NULL */
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d: Error NULL or empty token string, status = %d\n",__FUNCTION__, __LINE__, (int) status);
        goto exit;
    }

    while (*pTokenStr)
    {
        if (',' == *pTokenStr)
        {
            *pTokenStr = 0x00;
            pConf->tokens[index] = SMP_TEE_fetchInt(pIntStart);

            pIntStart = pTokenStr + 1;
            index++;
            if (index >= SMP_TEE_MAX_TOKENS)
                break;
        }
        pTokenStr++;
    }
    
    if (index < SMP_TEE_MAX_TOKENS)
    {
        /* last integer in list */
        pConf->tokens[index] = SMP_TEE_fetchInt(pIntStart);
        pConf->numTokens = index + 1;
    }

exit:

    return status;
}

static MSTATUS SMP_TEE_parseModule(ubyte *pModHead, ubyte *pModEnd)
{
    MSTATUS status = OK;
    ubyte moduleId[] = "modulenum=";
    ubyte modDesc[] = "modulename=";
    ubyte moduleIdStr[] = "moduleidstr=";
    ubyte tokenStr[] = "tokens=";
    ubyte *pValString = NULL; 
    ubyte4 valLen = 0;
    ubyte *pBuf = NULL;

    Tee_Config *pConfig = NULL;

    status = DIGI_CALLOC((void **) &pConfig, 1, sizeof(Tee_Config));
    if (OK != status)
        goto exit;

    status = ERR_INVALID_INPUT;
    pBuf = SMP_TEE_parseString(moduleId, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
        goto exit;
    else
        pConfig->moduleId = SMP_TEE_fetchInt(pBuf);
    
    pBuf = SMP_TEE_parseString(modDesc, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
    {
        goto exit;
    }
    else
    {
        pValString = SMP_TEE_fetchStr(pBuf, NULL, SMP_TEE_MAX_NAME_STR_LEN); 
        valLen = DIGI_STRLEN(pValString);

        status = DIGI_MALLOC((void **) &pConfig->modDesc, valLen + 1);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pConfig->modDesc, pValString, valLen);
        if (OK != status)
            goto exit;
        
        pConfig->modDesc[valLen] = 0x00;
    }

    status = ERR_INVALID_INPUT;
    pBuf = SMP_TEE_parseString(moduleIdStr, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
    {
        goto exit;
    }
    else
    {
        (void) SMP_TEE_fetchStr(pBuf, pConfig->deviceModuleIdStr, SMP_TEE_MAX_ID_STR_LEN);
    }

    pBuf = SMP_TEE_parseString(tokenStr, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
        goto exit;
    else
        pValString = SMP_TEE_fetchStr(pBuf, NULL, SMP_TEE_MAX_TOKEN_STR_LEN);

    status = SMP_TEE_parseTokenStr(pValString, pConfig);
    if (OK != status)
        goto exit;

    /* Store the config in the module */
    gModule.pConfig = pConfig; pConfig = NULL;

exit:

    if (NULL != pConfig)
    {
        if (NULL != pConfig->modDesc)
        {
            (void) DIGI_FREE((void **) &pConfig->modDesc);
        }
        (void) DIGI_FREE((void **) &pConfig);
    }

    return status;
}

/* Parse pkcs11 config file */
static MSTATUS SMP_TEE_parseConf(
    ubyte* pBufHead
)
{
    MSTATUS status = OK;
    ubyte provider[] = "providertype=";
    ubyte module[] = "[module]";
    ubyte *pModHead = NULL;
    ubyte *pModEnd = NULL;
    byteBoolean done = FALSE;

    /* validate providertype if it's part of the config */
    pModHead = SMP_TEE_parseString(provider, pBufHead);
    if (*pModHead !='\0')
    {
        ubyte4 providerType = SMP_TEE_fetchInt(pModHead);
        if (TAP_PROVIDER_TEE != providerType)
        {
            DB_PRINT("%s.%d: Provider value %d in config is not TEE.\n",__FUNCTION__, __LINE__, providerType);
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
        pModHead = SMP_TEE_parseString(module, pModHead);
        if (*pModHead == '\0')
        {
            status = ERR_INVALID_INPUT;
            break;
        }

        /* look for the next module */
        pModEnd = SMP_TEE_parseString(module, pModHead);
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
        status = SMP_TEE_parseModule(pModHead, pModEnd);
        if (OK != status)
        {
            DB_PRINT("%s.%d: Error parsing [module].\n",__FUNCTION__, __LINE__);
            goto exit;            
        }
    
        if (done)
        {
            break;
        }
        else
        {
            /* we allow only one [module] for now. Error */
            status = ERR_INVALID_INPUT;
            DB_PRINT("%s.%d: Multiple [module]s not currently supported.\n",__FUNCTION__, __LINE__);
            break;
        }
    }

exit:
    return status;
}
#endif /* #if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TEE__)) */
