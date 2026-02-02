/*
 * smp_nanoroot_util.c
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

/**
 * @file       smp_nanoroot_util.c
 * @brief      utility file for smp_nanoroot_api.c
 * @details    defines helper and utility functions required by smp_nanoroot_api.c
 */

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_NANOROOT__))

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>

#include "smp_nanoroot_api.h"
#include "smp_nanoroot.h"
#include "smp_nanoroot_parseConfig.h"
#include "common/mfmgmt.h"
#include "tap/tap_common.h"

#include "crypto/aes.h"
#include "crypto_interface/crypto_interface_nist_ctr_drbg.h"
#include "crypto_interface/crypto_interface_sha256.h"
#include "crypto_interface/crypto_interface_rsa.h"
#include "crypto_interface/crypto_interface_ecc.h"

#define CONF_FILE_DIR "/etc/digicert/"

static ubyte gpInitSeed[64] =
{
    0x1C,0x5F,0x0F,0x4C,0xDF,0x55,0x32,0x1B,0x73,0x4C,0x83,0x34,0x1D,0xB1,0x5E,0x8D,
    0x26,0xe4,0x4a,0xa7,0x8f,0xcc,0x69,0x06,0x87,0xe7,0x4c,0xfd,0xc2,0x76,0x20,0x3a,
    0xfc,0xbd,0x6e,0xf3,0x46,0x96,0x01,0x1e,0x5a,0xe1,0xcb,0xfe,0x5b,0x9c,0x51,0x77,
    0x40,0xd6,0x33,0x2b,0xc7,0x5b,0x9c,0x51,0x77,0x24,0xf1,0x79,0x2b,0xc7,0x5b,0x9c,
};

NROOTKdfElement *gpElementList = NULL;
ubyte4 gNROOTKdfEleCount = 0;

/* Global Mutex for protecting nanoroot modules */
extern RTOS_MUTEX gSmpNanoROOTMutex;

/* Global required to store the nanoroot conf details */
extern NanoROOT_Config *gpNanoROOTConfig;

MSTATUS NanoROOT_deInit();

void NanoROOT_FillError(TAP_Error* error, MSTATUS* pStatus, MSTATUS statusVal, const char* pErrString)
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

    error->tapErrorString.bufferLen = strnlen((const char*)pErrString, NanoROOTMAX_ERROR_BUFFER-1);
    snprintf((char *)error->tapErrorString.pBuffer, NanoROOTMAX_ERROR_BUFFER, "%s", pErrString);
    error->tapErrorString.pBuffer[error->tapErrorString.bufferLen] = 0;

exit:
    return;

}


/**
 * Extract string from buffer until delimiter or outBufSize
 * @param pBuf       Input buffer to read from
 * @param pOutBuf    Output buffer (if NULL, will allocate)
 * @param outBufSize Size of pOutBuf
 * @return Pointer to output buffer, or NULL on error
 */
static ubyte* NanoROOT_fetchStr(ubyte* pBuf, ubyte* pOutBuf, ubyte4 outBufSize)
{
    ubyte4 i = 0;
    ubyte *pVal = pOutBuf;
    ubyte4 size = 0;

    if (NULL == pBuf)
        return NULL;

    /* Guard against outBufSize being 0 */
    if (0 == outBufSize)
        return NULL;

    /* Find string length up to outBufSize - 1 (reserve space for null terminator) */
    while (i < (outBufSize - 1) && pBuf[i] != '\n' && pBuf[i] != '\0' && pBuf[i] != '\r')
    {
        size++;
        i++;
    }
    
    /* Check if string was truncated when using provided buffer */
    if (NULL != pOutBuf && i == (outBufSize - 1) && 
        pBuf[i] != '\n' && pBuf[i] != '\0' && pBuf[i] != '\r')
    {
        /* String is longer than buffer can hold */
        return NULL;
    }

    /* Allocate buffer if not provided */
    if (NULL == pVal)
    {
        pVal = MALLOC(size + 1);
        if (NULL == pVal)
        {
            return NULL;
        }
    }
    
    /* Copy string and null-terminate */
    if (size > 0)
    {
        (void) DIGI_MEMCPY(pVal, pBuf, size);
    }
    pVal[size] = '\0';

    return pVal;
}

static ubyte* NanoROOT_parseString(ubyte* pParse, ubyte* pBuf)
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

MOC_EXTERN MSTATUS NanoROOT_isPathRelative(const ubyte* pPathStr, const ubyte4 pathLen,
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


static MSTATUS NanoROOT_parseModule(ubyte *pModHead, ubyte *pModEnd)
{
    MSTATUS status = OK;
    ubyte moduleId[] = "modulenum=";
    ubyte modDesc[] = "modulename=";
    ubyte moduleIdStr[] = "moduleidstr=";
    ubyte credFile[] = "credfile=";
    ubyte *pValString = NULL;
    ubyte *pBuf = NULL;
    NanoROOT_Config *pConf = NULL;
    ubyte *pFileName = NULL;
    ubyte4 fileNameLen = 0;
    byteBoolean isPathRelative = TRUE;
    ubyte *pFullPath = NULL;
    ubyte4 confDirLen = 0;

    status = DIGI_CALLOC((void **) &pConf, 1, sizeof(NanoROOT_Config));
    if (OK != status)
        goto exit;

    pBuf = NanoROOT_parseString(moduleId, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    else
    {
        char *endptr = NULL;
        unsigned long tempVal;
        
        errno = 0;
        tempVal = strtoul((const char *)pBuf, &endptr, 10);
        
        /* Check for conversion errors */
        if (errno == ERANGE || endptr == (const char *)pBuf || tempVal > UINT_MAX)
        {
            DB_PRINT("%s.%d: Invalid modulenum value.\n", __FUNCTION__, __LINE__);
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        
        pConf->moduleId = (ubyte4)tempVal;
    }
    DB_PRINT("%s.%d: modulenum=%d.\n",__FUNCTION__, __LINE__, pConf->moduleId);

    pBuf = NanoROOT_parseString(modDesc, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    else
    {
        pConf->modDesc = NanoROOT_fetchStr(pBuf, NULL, NanoROOTMAX_SLOT_DESC_SZ);
        if (NULL == pConf->modDesc)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    DB_PRINT("%s.%d: modulename=%s.\n",__FUNCTION__, __LINE__, pConf->modDesc);

    status = ERR_INVALID_INPUT;
    pBuf = NanoROOT_parseString(moduleIdStr, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
    {
        goto exit;
    }
    else
    {
        pValString = NanoROOT_fetchStr(pBuf, NULL, 2*SHA256_RESULT_SIZE+1);
        if (NULL == pValString)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    DB_PRINT("%s.%d: moduleidstr=%s.\n",__FUNCTION__, __LINE__, pValString);

    /* Convert module id string to HEX */
    if (OK != (status = DIGI_convertHexString(
                    (const char *)pValString,
                    pConf->deviceModuleIdStr,
                    sizeof(pConf->deviceModuleIdStr))))
    {
        DB_PRINT("%s.%d: Error converting ID string \"%s\" to HEX value\n",
                 __FUNCTION__, __LINE__, pValString);
        goto exit;
    }

    /* credFile is mandatory */
    pBuf = NanoROOT_parseString(credFile, pModHead);
    if (*pBuf =='\0' || pBuf >= pModEnd)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    else
    {
        pFileName = NanoROOT_fetchStr(pBuf, NULL, PATH_MAX);
        if(NULL == pFileName)
        {
            DB_PRINT("%s.%d: Error in fetching pFileName.\n",__FUNCTION__, __LINE__);
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* Check for path traversal attempts */
        if (NULL != strstr((const char *)pFileName, ".."))
        {
            DB_PRINT("%s.%d: Error path traversal attempt detected in filename: %s\n",
                    __FUNCTION__, __LINE__, pFileName);
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        /* Validate path characters */
        status = NanoROOT_validateInput((sbyte*)pFileName, (sbyte *)NANOROOT_ALLOWED_PATH_CHARS);
        if (OK != status)
        {
            DB_PRINT("%s:%d Error: Invalid characters in path\n", __func__, __LINE__);
            goto exit;
        }
        
        fileNameLen = DIGI_STRLEN((sbyte*)pFileName);

        NanoROOT_isPathRelative(pFileName, fileNameLen, &isPathRelative);
        if(isPathRelative)
        {
#ifdef MANDATORY_BASE_PATH
            confDirLen = DIGI_STRLEN((const sbyte *)MANDATORY_BASE_PATH);
            status = DIGI_CALLOC((void **)&pFullPath, 1, confDirLen + fileNameLen + 1);
            if (OK != status)
            {
                DB_PRINT("%s.%d: Error allocating memory for credential file.\n",__FUNCTION__, __LINE__);
                goto exit;
            }

            status = DIGI_MEMCPY(&pFullPath[0], MANDATORY_BASE_PATH, confDirLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d: Error copying credential file dir.\n",__FUNCTION__, __LINE__);
                goto exit;
            }
#else
            confDirLen = DIGI_STRLEN((const sbyte *)CONF_FILE_DIR);
            status = DIGI_CALLOC((void **)&pFullPath, 1, confDirLen + fileNameLen + 1);
            if (OK != status)
            {
                DB_PRINT("%s.%d: Error allocating memory for credential file.\n",__FUNCTION__, __LINE__);
                goto exit;
            }

            status = DIGI_MEMCPY(&pFullPath[0], CONF_FILE_DIR, confDirLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d: Error copying credential file dir.\n",__FUNCTION__, __LINE__);
                goto exit;
            }
#endif
            status = DIGI_MEMCPY(&pFullPath[confDirLen], pFileName, fileNameLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d: Error copying credential file path.\n",__FUNCTION__, __LINE__);
                goto exit;
            }
            (void) DIGI_FREE((void **) &pFileName);
            pFileName = NULL;
            pConf->credentialFile.pBuffer = pFullPath;
            pConf->credentialFile.bufferLen = DIGI_STRLEN((sbyte*)pFullPath);
        }
        else
        {
            DB_PRINT("%s.%d: Error absolute file path %s not allowed..\n",__FUNCTION__, __LINE__, pFileName);
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        DB_PRINT("%s.%d: credFile=%s.\n",__FUNCTION__, __LINE__, pConf->credentialFile.pBuffer);
    }

    gpNanoROOTConfig = pConf;

exit:

    if (NULL != pFileName)
    {
        (void) DIGI_FREE((void **) &pFileName);
    }
    if (NULL != pValString)
    {
        (void) DIGI_FREE((void **) &pValString);
    }

    if (OK != status && NULL != pConf)
    {
        (void) DIGI_FREE((void **) &pConf->modDesc);
        (void) DIGI_FREE((void **) &pConf);
    }

    return status;
}

/* Parse nanoroot config file */
static MSTATUS NanoROOT_parseConf(ubyte* pBufHead)
{
    MSTATUS status = ERR_TAP_INVALID_TAP_PROVIDER;
    ubyte provider[] = "providertype=";
    ubyte module[] = "[module]";
    ubyte *pModHead = NULL;
    ubyte *pModEnd = NULL;
    byteBoolean done = FALSE;

    /* validate providertype if it's part of the config */
    pModHead = NanoROOT_parseString(provider, pBufHead);
    if (*pModHead !='\0')
    {
        char *endptr = NULL;
        unsigned long tempVal;
    
        errno = 0;
        tempVal = strtoul((const char *)pModHead, &endptr, 10);
    
        /* Check for conversion errors */
        if (errno == ERANGE || endptr == (const char *)pModHead || tempVal > UINT_MAX)
        {
            DB_PRINT("%s.%d: Invalid providertype value.\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_TAP_PROVIDER;
            goto exit;
        }
    
        ubyte4 providerType = (ubyte4)tempVal;
        if (TAP_PROVIDER_NANOROOT != providerType)
        {
            DB_PRINT("%s.%d: Provider value %d in config is not NanoROOT.\n",__FUNCTION__, __LINE__, providerType);
            goto exit;
        }
        DB_PRINT("%s.%d: providertype=NanoROOT.\n",__FUNCTION__, __LINE__);
    }
    else  /* reset pModHead */
    {
        pModHead = pBufHead;
    }

    while(!done)
    {
        /* look for where the next module begins */
        pModHead = NanoROOT_parseString(module, pModHead);
        if (*pModHead == '\0')
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* look for the next module */
        pModEnd = NanoROOT_parseString(module, pModHead);
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
        status = NanoROOT_parseModule(pModHead, pModEnd);
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
            /* we allow only one [module]. Error */
            status = ERR_INVALID_INPUT;
            DB_PRINT("%s.%d: Multiple [module]s not currently supported.\n",__FUNCTION__, __LINE__);
            goto exit;
        }
    }

    /* Parse credfile */
    if (TRUE == FMGMT_pathExists((const sbyte *)gpNanoROOTConfig->credentialFile.pBuffer, NULL))
    {
        DB_PRINT("%s.%d: Parsing credfile : %s\n",__FUNCTION__, __LINE__,
                gpNanoROOTConfig->credentialFile.pBuffer);

        status = NanoROOT_parseCredFile(gpNanoROOTConfig->credentialFile.pBuffer);
        if (OK != status)
        {
           status = ERR_FILE_BAD_DATA;
           DB_PRINT("%s.%d Error in parsing credfile. status =  %d\n",
                __func__, __LINE__, (int)status);
            goto exit;
        }
    }
    else
    {
        DB_PRINT("%s.%d: Error credfile %s does not exist.\n",__FUNCTION__, __LINE__,
                gpNanoROOTConfig->credentialFile.pBuffer);
        status = ERR_FILE_BAD_DATA;
        goto exit;
    }

exit:

    return status;
}

/*
 * Init routine called from SMP_NanoROOT_register API.
 * Allocate all necessary objects and also initialize module if config
 * file provided.
 */

MSTATUS NanoROOT_init(TAP_ConfigInfo *pConfigInfo)
{
    MSTATUS status = OK;
    byteBoolean isMutexLocked = FALSE;
    ubyte *pTmpConfig = NULL;

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    if (NULL == pConfigInfo || NULL == pConfigInfo->configInfo.pBuffer)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error NULL config, status = %d\n", __FUNCTION__, __LINE__, (int)status);
        NanoROOT_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    if (0 == pConfigInfo->configInfo.bufferLen)
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Error empty config, status = %d\n", __FUNCTION__, __LINE__, (int)status);
        NanoROOT_FillError(NULL, &status, ERR_INVALID_INPUT, "ERR_INVALID_INPUT");
        goto exit;  
    }

    status = RTOS_mutexCreate(&gSmpNanoROOTMutex, 0, 1);
    if(OK != status) {
        NanoROOT_FillError(NULL, &status, ERR_RTOS_MUTEX_CREATE, "ERR_RTOS_MUTEX_CREATE");
        DB_PRINT("%s.%d Mutex creation failed. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if (OK != (status = RTOS_mutexWait(gSmpNanoROOTMutex)))
        goto exit;

    isMutexLocked = TRUE;

    /* Parse configuration file */
    if (TAP_PROVIDER_NANOROOT != pConfigInfo->provider)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Error Provider is not NanoROOT, status  = %d\n", __FUNCTION__, __LINE__, (int)status);
        NanoROOT_FillError(NULL, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pTmpConfig, pConfigInfo->configInfo.bufferLen + 1);
    if (OK != status)
        goto exit;

    (void) DIGI_MEMCPY(pTmpConfig, pConfigInfo->configInfo.pBuffer, pConfigInfo->configInfo.bufferLen);
    pTmpConfig[pConfigInfo->configInfo.bufferLen] = '\0';

    status = NanoROOT_parseConf(pTmpConfig);
    if (OK != status)
    {
        status = ERR_FILE_BAD_DATA;
        goto exit;
    }

    gpNanoROOTConfig->cred_ctx.pFPElement = gpElementList;
    gpNanoROOTConfig->cred_ctx.numOfFPElement = gNROOTKdfEleCount;
    gpNanoROOTConfig->cred_ctx.pInitSeed = gpInitSeed;
    gpNanoROOTConfig->cred_ctx.initSeedLen = sizeof(gpInitSeed);
    gpNanoROOTConfig->cred_ctx.kdf = NanoROOTKDF_ANSI_X963;
    gpNanoROOTConfig->cred_ctx.mech = NanoROOTAES_256_CTR;

exit:
    if (NULL != pTmpConfig)
    {
        (void) DIGI_FREE((void **) &pTmpConfig);
    }

    if (TRUE == isMutexLocked)
    {
        RTOS_mutexRelease(gSmpNanoROOTMutex);
    }

    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);

    if(OK != status)
    {
        (void)NanoROOT_deInit();
    }

    return status;
}

/*
 * DeInit routine called from SMP_NanoROOT_unregister API.
 * Free all allocations done for the nanoroot modules.
 */
MSTATUS NanoROOT_deInit()
{
    MSTATUS status = OK;

    DB_PRINT("Begins %s()..\n", __FUNCTION__);


    if (NULL == gSmpNanoROOTMutex)
    {
        goto exit;
    }
    else
    {
        if (OK != (status = RTOS_mutexWait(gSmpNanoROOTMutex)))
            goto exit;
    }

    DIGI_FREE((void **) &gpElementList);
    gpElementList = NULL;

    if(gpNanoROOTConfig)
    {
        DIGI_FREE((void **) &gpNanoROOTConfig->modDesc);
        DIGI_FREE((void **) &gpNanoROOTConfig->credentialFile.pBuffer);
        DIGI_FREE((void **) &gpNanoROOTConfig);
        gpNanoROOTConfig = NULL;
    }

    (void) RTOS_mutexRelease(gSmpNanoROOTMutex);
    (void) RTOS_mutexFree(&gSmpNanoROOTMutex);
    gSmpNanoROOTMutex = NULL;

exit:

    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);

    return status;
}

#endif /* #if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_NANOROOT__)) */
