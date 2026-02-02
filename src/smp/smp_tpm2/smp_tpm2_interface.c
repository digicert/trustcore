/*
 * smp_tpm2_interface.c
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
 *@file      smp_tpm2_interface.c
 *@brief     NanoSMP provider Interface function definition that an application
 *           (NanoTAP) will use to communicate/manage TPM2 SMP module plugin.
 *@details   This header file contains  function definitions used by NanoTAP to
 *           communicate/manage TPM2 NanoSMP module plugin.
 */

#include "../../common/moptions.h"

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TPM2__))
#include "tpm2_lib/tpm2_types.h"
#include "tpm2_lib/fapi2/fapi2.h"
#include "smp_tpm2_interface.h"
#include "smp_tpm2_api.h"
#include "smp_tpm2.h"
#include "tpm2_lib/tcti/tcti.h"
#include "../../common/base64.h"
#include "../../common/moc_config.h"
#include "../../common/debug_console.h"

MOC_EXTERN_DATA_DEF TPM2_MODULE_CONFIG_SECTION *pgConfig = NULL;
RTOS_MUTEX tpm2SmpMutex = NULL;

typedef struct
{
    TPM2_MODULE_CONFIG_SECTION **ppModuleConfigSection;
    char *name;
} TPM2_PARSE_PARMS;

MSTATUS
TPM2_ParseModuleIdStr(ubyte *line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TPM2_PARSE_PARMS *pParseParms = (TPM2_PARSE_PARMS *)arg;
    char *pValString;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
    	return ERR_INVALID_ARG;
    }

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)pParseParms->name, '=', &offset)))
    {
        DB_PRINT("%s.%d: Error %d while seeking value for Module Id\n", __FUNCTION__, __LINE__, status);
        return status;
    }

    /* value is a number */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    sLen =  i + 2 - offset;
    status = DIGI_MALLOC((void **)&pValString, sLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Error allocating %d bytes for string value\n",__FUNCTION__, __LINE__, sLen);
    }
    else
    {
        status = DIGI_MEMCPY(pValString, line+offset, sLen-1);
        if (OK != status)
        {
            DB_PRINT("%s.%d: Error %d while copying string value\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
        pValString[sLen-1] = 0;
        pModuleConfigSection = (TPM2_MODULE_CONFIG_SECTION *)*(pParseParms->ppModuleConfigSection);
        
        /* Convert module id string to HEX */
        if (OK != (status = DIGI_convertHexString(
                        (const char *)pValString,
                        pModuleConfigSection->configuredModuleIdStr, 
                        sizeof(pModuleConfigSection->configuredModuleIdStr))))
        {
            DB_PRINT("%s.%d: Error converting ID string \"%s\" to HEX value\n",__FUNCTION__, __LINE__, pValString);
            goto exit;
        }

        /* Save the location and length of Module ID string */
        pModuleConfigSection->pConfiguredModuleIdStrStart = (ubyte *)(line + offset);
        pModuleConfigSection->configuredModuleIdStrLen = sLen-1;

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
    }

exit:
    if (NULL != pValString)
    {
        DIGI_FREE((void **)&pValString);
    }

    return status;
}

MSTATUS
TPM2_ParseModuleId(ubyte *line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TPM2_PARSE_PARMS *pParseParms = (TPM2_PARSE_PARMS *)arg;
    char *pValString;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
    	return ERR_INVALID_ARG;
    }

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)pParseParms->name, '=', &offset)))
    {
        DB_PRINT("%s.%d: Error %d while seeking value for Module Num\n", __FUNCTION__, __LINE__, status);
        return status;
    }

    /* value is a number */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    sLen =  i + 2 - offset;
    status = DIGI_MALLOC((void **)&pValString, sLen);
    if (OK != status)
    {
        DB_PRINT("TPM2_ParseModuleId: Error allocating %d bytes for string value\n", sLen);
    }
    else
    {
        (void) DIGI_MEMCPY(pValString, line+offset, sLen-1);
        pValString[sLen-1] = 0;
        pModuleConfigSection = (TPM2_MODULE_CONFIG_SECTION *)*(pParseParms->ppModuleConfigSection);

        /* Convert module id */
        pValString[sLen-1] = 0;
        pModuleConfigSection = (TPM2_MODULE_CONFIG_SECTION *)*(pParseParms->ppModuleConfigSection);

        pModuleConfigSection->moduleId = DIGI_ATOL((const sbyte *)pValString, NULL);

        DIGI_FREE((void **)&pValString);

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
    }

    return status;
}

MSTATUS
TPM2_ParseProviderValue(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    char *valString;
    TAP_PROVIDER provider;
    MOC_UNUSED(arg);

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)"providerType", '=', &offset)))
    {
        return status;
    }

    /* value is a number */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    sLen =  i + 2 - offset;
    status = DIGI_MALLOC((void **)&valString, sLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d: ParseIntVal: Error allocating %d bytes for integer value\n", __FUNCTION__, __LINE__, sLen);
    }
    else
    {
        (void) DIGI_MEMCPY(valString, line+offset, sLen-1);
        valString[sLen-1] = 0;
        provider = DIGI_ATOL((const sbyte *)valString, NULL);

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
        DIGI_FREE((void **)&valString);

        if (TAP_PROVIDER_TPM2 != provider)
        {
            status = ERR_TAP_INVALID_TAP_PROVIDER;
        }
    }

    return status;
}

MSTATUS
TPM2_ParseIntValue(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TPM2_PARSE_PARMS *pParseParms = (TPM2_PARSE_PARMS *)arg;
    char *valString;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
        return ERR_INVALID_ARG;
    }
    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)pParseParms->name, '=', &offset)))
    {
        return status;
    }

    /* value is a number */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    sLen =  i + 2 - offset;
    status = DIGI_MALLOC((void **)&valString, sLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Error allocating %d bytes for integer value\n",__FUNCTION__, __LINE__, sLen);
    }
    else
    {
        (void) DIGI_MEMCPY(valString, line+offset, sLen-1);
        valString[sLen-1] = 0;
        pModuleConfigSection = (TPM2_MODULE_CONFIG_SECTION *)*(pParseParms->ppModuleConfigSection);

        pModuleConfigSection->modulePort = DIGI_ATOL((const sbyte *)valString, NULL);

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
        DIGI_FREE((void **)&valString);
    }

    return status;
}

MSTATUS
TPM2_ParseCredentials(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TPM2_PARSE_PARMS *pParseParms = (TPM2_PARSE_PARMS *)arg;
    ubyte *pValString = NULL;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
        return ERR_INVALID_ARG;
    }

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)pParseParms->name, '=', &offset)))
    {
        DB_PRINT("%s.%d: Error %d while parsing value for key - %s\n", __FUNCTION__, __LINE__, status, pParseParms->name);
        return status;
    }

    /* value is a number */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    sLen =  i + 2 - offset;
    status = DIGI_MALLOC((void **)&pValString, sLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Error allocating %d bytes for string value\n",__FUNCTION__, __LINE__, sLen);
    }
    else
    {
        (void) DIGI_MEMCPY(pValString, line+offset, sLen-1);
        pValString[sLen-1] = 0;
        pModuleConfigSection = (TPM2_MODULE_CONFIG_SECTION *)*(pParseParms->ppModuleConfigSection);

        /* We have credentials file name in pValString */
        pModuleConfigSection->credentialFile.pBuffer = (ubyte *)pValString;
        pModuleConfigSection->credentialFile.bufferLen = sLen;

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
    }

    return status;
}

MSTATUS
TPM2_ParseStrValue(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen, eolOffset=0;
    TPM2_PARSE_PARMS *pParseParms = (TPM2_PARSE_PARMS *)arg;
    ubyte *pValString = NULL;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
        return ERR_INVALID_ARG;
    }

    if (OK != (status = CONFIG_readToEOL((sbyte *)line, bytesLeft, &eolOffset)))
    {
        DB_PRINT("%s.%d: Error %d while parsing value for key - %s\n",
                __FUNCTION__, __LINE__, status, pParseParms->name);
        return status;
    }
    /*Read value only till end-of-line*/
    status = CONFIG_gotoValue(line, eolOffset, (const sbyte *)pParseParms->name, '=', &offset);

    if (OK != status)
    {
        /* Continue to process with empty value*/
        if (  (ERR_CONFIG_NO_VALUE == status)
           || (ERR_CONFIG_MISSING_VALUE == status)
           )
        {
            pValString = NULL;
            sLen = 0;
            status = OK;
        }
        else
        {
            DB_PRINT("%s.%d: Error %d while parsing value for key - %s\n", __FUNCTION__, __LINE__, status, pParseParms->name);
            return status;
        }
    }
    else
    {
        /* value is a number */
        for (i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
        {
        }

        /* go back and look for space */
        for (--i; i >= offset && DIGI_ISSPACE(line[i]); --i)
        {
        }

        sLen = i + 2 - offset;
        status = DIGI_MALLOC((void **)&pValString, sLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d: Error allocating %d bytes for string value\n", __FUNCTION__, __LINE__, sLen);
        }
        else
        {
            (void) DIGI_MEMCPY(pValString, line + offset, sLen - 1);
            pValString[sLen - 1] = 0;
        }
    }

    pModuleConfigSection = (TPM2_MODULE_CONFIG_SECTION *)*(pParseParms->ppModuleConfigSection);
    /* Tell the parser we've eaten the rest of the line */
    *bytesUsed = CONFIG_nextLine(line, bytesLeft);
    pModuleConfigSection->moduleName.pBuffer = (ubyte *)pValString;
    pModuleConfigSection->moduleName.bufferLen = sLen;
    return status;
}

MSTATUS
TPM2_ParseModuleConfigSection(ubyte* line, ubyte4 bytesLeft, void* arg,
    ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0;
    TPM2_PARSE_PARMS *pParseParms = (TPM2_PARSE_PARMS *)arg;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
        return ERR_INVALID_ARG;
    }

    if (OK != (status = CONFIG_gotoSection(line, bytesLeft, 
                    (const sbyte *)pParseParms->name, &offset)))
    {
        DB_PRINT("%s.%d: Error %d while seeking section %s\n", __FUNCTION__, __LINE__, status, pParseParms->name);
        return status;
    }

    /* Allocate Module Config Section */
    if (OK != (status = DIGI_MALLOC((void **)&pModuleConfigSection, 
                    sizeof(*pModuleConfigSection))))
    {
        DB_PRINT("%s.%d: Error allocating %d bytes for ModuleconfigSection\n",__FUNCTION__, __LINE__, sizeof(*pModuleConfigSection));
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pModuleConfigSection, 0, 
            sizeof(*pModuleConfigSection));

    /* Add new config file name node to top of the list */
    pModuleConfigSection->pNext = *(pParseParms->ppModuleConfigSection);
    *(pParseParms->ppModuleConfigSection) = pModuleConfigSection;

    /* Tell the parser we've eaten the rest of the line */
    *bytesUsed = CONFIG_nextLine(line, bytesLeft);
exit:

    return status;
}

static MSTATUS
TPM2_ParsePlatformAuth(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen, eolOffset=0;
    TPM2_PARSE_PARMS *pParseParms = (TPM2_PARSE_PARMS *)arg;
    ubyte *pValString = NULL;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
        return ERR_INVALID_ARG;
    }

    if (OK != (status = CONFIG_readToEOL((sbyte *)line, bytesLeft, &eolOffset)))
    {
        DB_PRINT("%s.%d: Error %d while parsing value for key - %s\n",
                __FUNCTION__, __LINE__, status, pParseParms->name);
        return status;
    }
    /*Read value only till end-of-line*/
    status = CONFIG_gotoValue(line, eolOffset, (const sbyte *)pParseParms->name, '=', &offset);

    if (OK != status)
    {
        /* Continue to process with empty value*/
        if (  (ERR_CONFIG_NO_VALUE == status)
           || (ERR_CONFIG_MISSING_VALUE == status)
           )
        {
            pValString = NULL;
            sLen = 0;
            status = OK;
        }
        else
        {
            DB_PRINT("%s.%d: Error %d while parsing value for key - %s\n", __FUNCTION__, __LINE__, status, pParseParms->name);
            return status;
        }
    }
    else
    {
        /* value is a number */
        for (i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
        {
        }

        /* go back and look for space */
        for (--i; i >= offset && DIGI_ISSPACE(line[i]); --i)
        {
        }

        sLen = i + 1 - offset;
        status = DIGI_MALLOC((void **)&pValString, sLen+1);
        if (OK != status)
        {
            DB_PRINT("%s.%d: Error allocating %d bytes for string value\n", __FUNCTION__, __LINE__, sLen);
	    goto exit;
        }
        else
        {
            (void) DIGI_MEMCPY(pValString, line + offset, sLen);
            pValString[sLen] = 0;
        }
    }

    pModuleConfigSection = (TPM2_MODULE_CONFIG_SECTION *)*(pParseParms->ppModuleConfigSection);
    /* Tell the parser we've eaten the rest of the line */
    *bytesUsed = CONFIG_nextLine(line, bytesLeft);

    if ( (NULL != pValString) && (0 < sLen) )
    {
        /* BASE64 decode authentication value */
        status = BASE64_decodeMessage((const ubyte*)pValString, sLen,
                        &(pModuleConfigSection->platformAuth.pBuffer),
                        &(pModuleConfigSection->platformAuth.bufferLen));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to decode base64 blob, status=%d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }

exit:
    return status;
}

static MSTATUS TPM2_validateProviderType(TAP_Buffer *pConfigBuffer)
{
    static CONFIG_ConfigItem configItems[] = {
        {(const sbyte *)"providerType", 0, 0},
        {(const sbyte *)NULL, 0, 0}
    };

    configItems[0].callback = TPM2_ParseProviderValue;
    configItems[0].callback_arg = NULL;

    return CONFIG_parseData(
        pConfigBuffer->pBuffer, pConfigBuffer->bufferLen, configItems);
}

MOC_EXTERN MSTATUS TPM2_parseConfiguration(TAP_Buffer *pConfigBuffer)
{
    MSTATUS status = OK;
    static CONFIG_ConfigItem configItems[] = {
        {(const sbyte *)"[module]", 0, 0},
        {(const sbyte *)"modulename", 0, 0},
        {(const sbyte *)"moduleport", 0, 0},
        {(const sbyte *)"moduleidstr", 0, 0},
        {(const sbyte *)"modulenum", 0, 0},
        {(const sbyte *)"credfile", 0, 0},
        {(const sbyte *)"platformauth", 0, 0},
        {(const sbyte *)NULL, 0, 0}
    };
    TPM2_PARSE_PARMS parseParms[sizeof(configItems)/sizeof(CONFIG_ConfigItem)];
    TPM2_PARSE_PARMS *pParseParms;
    ubyte *pConfig = NULL;
    ubyte4 configLen = 0;

    if ((NULL == pConfigBuffer) || (0 == pConfigBuffer->bufferLen) 
            || (NULL == pConfigBuffer->pBuffer))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, Input pointer = %p,"
                "Buffer Len = %d, Configuration buffer = %p\n", 
                __FUNCTION__, __LINE__, pConfigBuffer,
                pConfigBuffer ? pConfigBuffer->bufferLen : 0,
                pConfigBuffer ? pConfigBuffer->pBuffer : NULL);
        goto exit;
    }

    pConfig = pConfigBuffer->pBuffer;
    configLen = pConfigBuffer->bufferLen;

    pParseParms = &parseParms[0];

    configItems[0].callback = TPM2_ParseModuleConfigSection;
    pParseParms->name = (char *)configItems[0].key;
    pParseParms->ppModuleConfigSection = &pgConfig;
    configItems[0].callback_arg = pParseParms;

    pParseParms++;

    configItems[1].callback = TPM2_ParseStrValue;
    pParseParms->name = (char *)configItems[1].key;
    pParseParms->ppModuleConfigSection = &pgConfig;
    configItems[1].callback_arg = pParseParms;

    pParseParms++;

    configItems[2].callback = TPM2_ParseIntValue;
    pParseParms->name = (char *)configItems[2].key;
    pParseParms->ppModuleConfigSection = &pgConfig;
    configItems[2].callback_arg = pParseParms;

    pParseParms++;

    configItems[3].callback = TPM2_ParseModuleIdStr;
    pParseParms->name = (char *)configItems[3].key;
    pParseParms->ppModuleConfigSection = &pgConfig;
    configItems[3].callback_arg = pParseParms;

    pParseParms++;

    configItems[4].callback = TPM2_ParseModuleId;
    pParseParms->name = (char *)configItems[4].key;
    pParseParms->ppModuleConfigSection = &pgConfig;
    configItems[4].callback_arg = pParseParms;

    pParseParms++;

    configItems[5].callback = TPM2_ParseCredentials;
    pParseParms->name = (char *)configItems[5].key;
    pParseParms->ppModuleConfigSection = &pgConfig;
    configItems[5].callback_arg = pParseParms;

    pParseParms++;

    configItems[6].callback = TPM2_ParsePlatformAuth;
    pParseParms->name = (char *)configItems[6].key;
    pParseParms->ppModuleConfigSection = &pgConfig;
    configItems[6].callback_arg = pParseParms;


    status = CONFIG_parseData(pConfig, configLen, configItems);

exit:
    return status;
}

/* Should be only be called once by the main thread of the calling process
   prior to any of the process threads commencing SMP operations */
MOC_EXTERN MSTATUS SMP_TPM2_register(
        TAP_PROVIDER type,
        TAP_SMPVersion version,
        TAP_Version tapVersion,
        TAP_ConfigInfo *pConfigInfo,
        TAP_CmdCodeList *pRegisteredOpcodes
)
{
    MSTATUS status = OK;
    ubyte8 minVer = 0;
    ubyte8 inputVer = 0;
    ubyte4 apiCount = 0;
    TPM2_MODULE_CONFIG_SECTION *pModuleInfo = NULL;
    TctiContextInitIn tctiCtx = {0};

    if ((NULL == pConfigInfo) || 
            (NULL == pRegisteredOpcodes))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pConfigBuffer = %p,"
                "pRegisteredOpcodes = %p\n", 
                __FUNCTION__, __LINE__, pConfigInfo,
                pRegisteredOpcodes);
        goto exit;
    }

    status = RTOS_mutexCreate(&tpm2SmpMutex, 0, 1);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create mutex. error = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    status = RTOS_mutexWait(tpm2SmpMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to wait on mutex. error = %d",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Version check */
    minVer = (((ubyte8)SMP_VERSION_MAJOR << 32) | 
            ((ubyte8)SMP_VERSION_MINOR));
    inputVer = (((ubyte8)version.major << 32) | 
            ((ubyte8)version.minor));

    if (inputVer < minVer)
    {
        status = ERR_SMP_UNSUPPORTED_VERSION;
        DB_PRINT("%s.%d input SMP version less than min version, input Version = %d,"
                "minimum Version = %d\n",
                __FUNCTION__, __LINE__, inputVer, minVer);
        goto exit;
    }

    /* Ensure the provider type is correct if one is provided */
    status = TPM2_validateProviderType(&pConfigInfo->configInfo);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error %d parsing provider type from configuration\n", 
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Parse Config buffer and identify device and 
       their connection information 
     */
    status = TPM2_parseConfiguration(&pConfigInfo->configInfo);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error %d parsing configuration\n", 
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Setup all discovered modules */
    pModuleInfo = pgConfig;

    /* shred-context is supported only for 1 module */
    if (TRUE == pConfigInfo->useSharedHandle)
    {
        if (NULL != pModuleInfo->pNext)
        {
            status = ERR_UNSUPPORTED_OPERATION;
            DB_PRINT("%s.%d TPM2 supports only 1 module when `sharedcontext` is enabled\n",
                    __FUNCTION__, __LINE__);
            goto exit;
        }

        tctiCtx.serverNameLen = pModuleInfo->moduleName.bufferLen;
        tctiCtx.pServerName = pModuleInfo->moduleName.pBuffer;
        tctiCtx.serverPort = pModuleInfo->modulePort;

        if (TSS2_RC_SUCCESS != TSS2_TCTI_sharedContextInit(&tctiCtx) )
        {
            status = ERR_TAP_RC_TCTI_INSUFFICIENT_CONTEXT;
            DB_PRINT("%s.%d Shared TCTI context initialization failure\n",
                    __FUNCTION__, __LINE__);
            goto exit;
        }
    }

    while (pModuleInfo)
    {
        /* Set the configuration received from TAPS for reuseDeviceFD i.e. open close device handle only once */
        pModuleInfo->reuseDeviceFd = pConfigInfo->useSharedHandle;
        /* Allocate Mutex per module */
        status = RTOS_mutexCreate(&pModuleInfo->moduleMutex, 0, 1);
        if (OK != status)
            goto exit;

        pModuleInfo = pModuleInfo->pNext;
    }

    status = TPM2_validateModuleList(pgConfig); 
    if (OK != status)
    {
        DB_PRINT("%s.%d Error %d Validating Module list\n",
                __FUNCTION__, __LINE__, status);
    }

    /* Update opcode table */
    pRegisteredOpcodes->listLen = SMP_CC_LAST;
    status = DIGI_CALLOC((void **)&(pRegisteredOpcodes->pCmdList), 1,
            sizeof(SMP_CC) * pRegisteredOpcodes->listLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error %d allocating memory for command list\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    apiCount = 0;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_INIT_MODULE;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_INIT_TOKEN;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_UNINIT_MODULE;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_PUBLIC_KEY;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_FREE_PUBLIC_KEY;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_PRIVATE_KEY_BLOB;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_PUBLIC_KEY_BLOB;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_DUPLICATEKEY;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_IMPORTDUPLICATEKEY;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_EXPORT_OBJECT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_CREATE_ASYMMETRIC_KEY;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_CREATE_SYMMETRIC_KEY;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_IMPORT_EXTERNAL_KEY;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_SIGN_DIGEST;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_SIGN_BUFFER;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_VERIFY;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_ENCRYPT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_DECRYPT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_MODULE_LIST;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_EXPORT_OBJECT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_SERIALIZE_OBJECT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_IMPORT_OBJECT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_MODULE_INFO;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_RANDOM;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_TRUSTED_DATA;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_UPDATE_TRUSTED_DATA;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_OBJECT_LIST;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_CREATE_OBJECT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_DELETE_OBJECT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_POLICY_STORAGE;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_SET_POLICY_STORAGE;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_SEAL_WITH_TRUSTED_DATA;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_UNSEAL_WITH_TRUSTED_DATA;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_SMP_GET_QUOTE;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_INIT_OBJECT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_TOKEN_LIST;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_FREE_MODULE_LIST;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_UNWRAP_KEY_VALIDATED_SECRET;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_UNINIT_TOKEN;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_UNINIT_OBJECT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_ASSOCIATE_MODULE_CREDENTIALS;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_DIGEST;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_STIR_RANDOM;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_SELF_TEST;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_SELF_TEST_POLL;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_FREE_SIGNATURE_BUFFER;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_GET_MODULE_CAPABILITY;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_EVICT_OBJECT;
    pRegisteredOpcodes->pCmdList[apiCount++] = SMP_CC_PERSIST_OBJECT;

exit:

    if (NULL != tpm2SmpMutex)
        RTOS_mutexRelease(tpm2SmpMutex);

    return status;
}

/* Should be only be called once by the main thread of the calling process
   after all the threads using this module have completed their SMP related
   operations */
MOC_EXTERN MSTATUS SMP_TPM2_unregister()
{
    MSTATUS status = OK;
    TPM2_MODULE_CONFIG_SECTION *pModuleInfo = NULL;
    TPM2_MODULE_CONFIG_SECTION *pNextModuleInfo = NULL;

    if (NULL != tpm2SmpMutex)
    {
        status = RTOS_mutexWait(tpm2SmpMutex);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to wait on mutex for TPM2_SMP=%p, status=%d\n",
                    __FUNCTION__, __LINE__, tpm2SmpMutex, status);
            goto exit;
        }
        pModuleInfo = pgConfig;

        while (pModuleInfo)
        {
            pNextModuleInfo = pModuleInfo->pNext;

            /* Uninit shared context */
            if ( TRUE == pModuleInfo->reuseDeviceFd )
            {
                TSS2_TCTI_sharedContextUninit();
            }

            /* Free */
            if (pModuleInfo->moduleName.pBuffer)
            {
                DIGI_FREE((void **)&pModuleInfo->moduleName.pBuffer);
                pModuleInfo->moduleName.pBuffer = NULL;
                pModuleInfo->moduleName.bufferLen = 0;
            }
            if(pModuleInfo->credentialFile.pBuffer)
            {
                DIGI_FREE((void **)&pModuleInfo->credentialFile.pBuffer);
                pModuleInfo->credentialFile.pBuffer = NULL;
                pModuleInfo->credentialFile.bufferLen = 0;
            }
            if(pModuleInfo->platformAuth.pBuffer)
            {
                DIGI_FREE((void **)&pModuleInfo->platformAuth.pBuffer);
                pModuleInfo->platformAuth.pBuffer = NULL;
                pModuleInfo->platformAuth.bufferLen = 0;
            }
            RTOS_mutexFree(&pModuleInfo->moduleMutex);

            DIGI_FREE((void **)&pModuleInfo);

            pModuleInfo = pNextModuleInfo;
        }
        pgConfig = NULL;

        RTOS_mutexRelease(tpm2SmpMutex);
        RTOS_mutexFree(&tpm2SmpMutex);
    }

exit:
    return status;
}

MOC_EXTERN MSTATUS SMP_TPM2_dispatcher(
        TAP_RequestContext *pCtx,
        SMP_CmdReq *pCmdReq,
        SMP_CmdRsp *pCmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , TAP_ErrorAttributes *pErrorRules
       , TAP_ErrorAttributes **ppErrAttrReturned
#endif
)
{
    MSTATUS status = ERR_GENERAL;
    ubyte4 cmdCode = SMP_CC_INVALID;

    if (!pCmdReq || !pCmdRsp)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
        status = ERR_NULL_POINTER;
        goto exit;
    }

    cmdCode = pCmdReq->cmdCode;
    pCmdRsp->cmdCode = pCmdReq->cmdCode;

    switch (cmdCode)
    {
#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_LIST__
    case SMP_CC_GET_MODULE_LIST                          :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getModuleList,
                pCmdReq->reqParams.getModuleList.pModuleAttributes,
                &(pCmdRsp->rspParams.getModuleList.moduleList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_MODULE_LIST__
    case SMP_CC_FREE_MODULE_LIST                         :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, freeModuleList,
                (pCmdReq->reqParams.freeModuleList.pModuleList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_INFO__
    case SMP_CC_GET_MODULE_INFO                  :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getModuleInfo,
                pCmdReq->reqParams.getModuleInfo.moduleId,
                pCmdReq->reqParams.getModuleInfo.pCapabilitySelectCriterion,
                &(pCmdRsp->rspParams.getModuleInfo.moduleCapabilties)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_SLOTS__
    case SMP_CC_GET_MODULE_SLOTS                         :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getModuleSlots,
                pCmdReq->reqParams.getModuleSlots.moduleHandle,
                &(pCmdRsp->rspParams.getModuleSlots.moduleSlotList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TOKEN_LIST__
    case SMP_CC_GET_TOKEN_LIST                           :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getTokenList,
                pCmdReq->reqParams.getTokenList.moduleHandle,
                pCmdReq->reqParams.getTokenList.tokenType,
                pCmdReq->reqParams.getTokenList.pTokenAttributes,
                &(pCmdRsp->rspParams.getTokenList.tokenIdList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TOKEN_INFO__
    case SMP_CC_GET_TOKEN_INFO                           :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getTokenInfo,
                pCmdReq->reqParams.getTokenInfo.moduleHandle,
                pCmdReq->reqParams.getTokenInfo.tokenType,
                pCmdReq->reqParams.getTokenInfo.tokenId,
                pCmdReq->reqParams.getTokenInfo.pCapabilitySelectAttributes,
                &(pCmdRsp->rspParams.getTokenInfo.tokenAttributes)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_OBJECT_LIST__
    case SMP_CC_GET_OBJECT_LIST                          :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getObjectList,
                pCmdReq->reqParams.getObjectList.moduleHandle,
                pCmdReq->reqParams.getObjectList.tokenHandle,
                pCmdReq->reqParams.getObjectList.pObjectAttributes,
                &(pCmdRsp->rspParams.getObjectList.objectIdList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_OBJECT_INFO__
    case SMP_CC_GET_OBJECT_INFO                          :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getObjectInfo,
                pCmdReq->reqParams.getObjectInfo.moduleHandle,
                pCmdReq->reqParams.getObjectInfo.tokenHandle,
                pCmdReq->reqParams.getObjectInfo.objectHandle,
                pCmdReq->reqParams.getObjectInfo.objectId,
                pCmdReq->reqParams.getObjectInfo.pCapabilitySelectAttributes,
                &(pCmdRsp->rspParams.getObjectInfo.objectAttributes)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_PROVISION_MODULE__
    case SMP_CC_PROVISION_MODULE                         :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, provisionModule,
                pCmdReq->reqParams.provisionModule.moduleHandle,
                pCmdReq->reqParams.provisionModule.pModuleProvisionAttributes
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_RESET_MODULE__
    case SMP_CC_RESET_MODULE                             :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, resetModule,
                pCmdReq->reqParams.resetModule.moduleHandle,
                pCmdReq->reqParams.resetModule.pModuleProvisionAttributes
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_PROVISION_TOKEN__
    case SMP_CC_PROVISION_TOKEN                          :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, provisionTokens,
                pCmdReq->reqParams.provisionTokens.moduleHandle,
                pCmdReq->reqParams.provisionTokens.pTokenProvisionAttributes,
                &(pCmdRsp->rspParams.provisionTokens.tokenIdList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_RESET_TOKEN__
    case SMP_CC_RESET_TOKEN                              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, resetToken,
                pCmdReq->reqParams.resetToken.moduleHandle,
                pCmdReq->reqParams.resetToken.tokenHandle,
                pCmdReq->reqParams.resetToken.pTokenProvisionAttributes
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DELETE_TOKEN__
    case SMP_CC_DELETE_TOKEN                             :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, deleteToken,
                pCmdReq->reqParams.deleteToken.moduleHandle,
                pCmdReq->reqParams.deleteToken.tokenHandle,
                pCmdReq->reqParams.deleteToken.pTokenProvisionAttributes
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_MODULE__
    case SMP_CC_INIT_MODULE                              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, initModule,
                pCmdReq->reqParams.initModule.moduleId,
                pCmdReq->reqParams.initModule.pModuleAttributes,
                pCmdReq->reqParams.initModule.pCredentialList,
                &(pCmdRsp->rspParams.initModule.moduleHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_MODULE__
    case SMP_CC_UNINIT_MODULE                            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, uninitModule,
                pCmdReq->reqParams.uninitModule.moduleHandle
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_MODULE_CREDENTIALS__
    case SMP_CC_ASSOCIATE_MODULE_CREDENTIALS             :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, associateModuleCredentials,
                pCmdReq->reqParams.associateModuleCredentials.moduleHandle,
                pCmdReq->reqParams.associateModuleCredentials.pEntityCredentialList
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_TOKEN__
    case SMP_CC_INIT_TOKEN                               :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, initToken,
                pCmdReq->reqParams.initToken.moduleHandle,
                pCmdReq->reqParams.initToken.pTokenAttributes,
                pCmdReq->reqParams.initToken.tokenId,
                pCmdReq->reqParams.initToken.pCredentialList,
                &(pCmdRsp->rspParams.initToken.tokenHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_TOKEN__
    case SMP_CC_UNINIT_TOKEN                             :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, uninitToken,
                pCmdReq->reqParams.uninitToken.moduleHandle,
                pCmdReq->reqParams.uninitToken.tokenHandle
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS__
    case SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, associateTokenCredentials,
                pCmdReq->reqParams.associateTokenCredentials.moduleHandle,
                pCmdReq->reqParams.associateTokenCredentials.tokenHandle,
                pCmdReq->reqParams.associateTokenCredentials.pCredentialList
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_OBJECT__
    case SMP_CC_INIT_OBJECT                              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, initObject,
                pCmdReq->reqParams.initObject.moduleHandle,
                pCmdReq->reqParams.initObject.tokenHandle,
                pCmdReq->reqParams.initObject.objectIdIn,
                pCmdReq->reqParams.initObject.pObjectAttributes,
                pCmdReq->reqParams.initObject.pCredentialList,
                &(pCmdRsp->rspParams.initObject.objectHandle),
                &(pCmdRsp->rspParams.initObject.objectIdOut)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_IMPORT_OBJECT__
    case SMP_CC_IMPORT_OBJECT                              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, importObject,
                pCmdReq->reqParams.importObject.moduleHandle,
                pCmdReq->reqParams.importObject.tokenHandle,
                pCmdReq->reqParams.importObject.pBlob,
                pCmdReq->reqParams.importObject.pObjectAttributes,
                pCmdReq->reqParams.importObject.pCredentialList,
                &(pCmdRsp->rspParams.importObject.objectAttributesOut),
                &(pCmdRsp->rspParams.importObject.objectHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_OBJECT__
    case SMP_CC_UNINIT_OBJECT                            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, uninitObject,
                pCmdReq->reqParams.unintObject.moduleHandle,
                pCmdReq->reqParams.unintObject.tokenHandle,
                pCmdReq->reqParams.unintObject.objectHandle
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_EVICT_OBJECT__
    case SMP_CC_EVICT_OBJECT                                :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, evictObject,
                pCmdReq->reqParams.evictObject.moduleHandle,
                pCmdReq->reqParams.evictObject.pObjectId,
                pCmdReq->reqParams.evictObject.pAttributes
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_PERSIST_OBJECT__
    case SMP_CC_PERSIST_OBJECT:
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, persistObject,
                pCmdReq->reqParams.persistObject.moduleHandle,
                pCmdReq->reqParams.persistObject.keyHandle,
                pCmdReq->reqParams.persistObject.pObjectId
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS__
    case SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS             :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, associateObjectCredentials,
                pCmdReq->reqParams.associateObjectCredentials.moduleHandle,
                pCmdReq->reqParams.associateObjectCredentials.tokenHandle,
                pCmdReq->reqParams.associateObjectCredentials.objectHandle,
                pCmdReq->reqParams.associateObjectCredentials.pCredentialsList
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY__
    case SMP_CC_VERIFY                                   :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, verify,
                pCmdReq->reqParams.verify.moduleHandle,
                pCmdReq->reqParams.verify.tokenHandle,
                pCmdReq->reqParams.verify.keyHandle,
                pCmdReq->reqParams.verify.pMechanism,
                pCmdReq->reqParams.verify.pDigest,
                pCmdReq->reqParams.verify.pSignature,
                &(pCmdRsp->rspParams.verify.signatureValid)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_INIT__
    case SMP_CC_VERIFY_INIT                              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, verifyInit,
                pCmdReq->reqParams.verifyInit.moduleHandle,
                pCmdReq->reqParams.verifyInit.tokenHandle,
                pCmdReq->reqParams.verifyInit.keyHandle,
                pCmdReq->reqParams.verifyInit.pMechanism,
                &(pCmdRsp->rspParams.verifyInit.opContext)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_UPDATE__
    case SMP_CC_VERIFY_UPDATE                            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, verifyUpdate,
                pCmdReq->reqParams.verifyUpdate.moduleHandle,
                pCmdReq->reqParams.verifyUpdate.tokenHandle,
                pCmdReq->reqParams.verifyUpdate.keyHandle,
                pCmdReq->reqParams.verifyUpdate.pBuffer,
                pCmdReq->reqParams.verifyUpdate.opContext
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_FINAL__
    case SMP_CC_VERIFY_FINAL                             :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, verifyFinal,
                pCmdReq->reqParams.verifyFinal.moduleHandle,
                pCmdReq->reqParams.verifyFinal.tokenHandle,
                pCmdReq->reqParams.verifyFinal.keyHandle,
                pCmdReq->reqParams.verifyFinal.opContext,
                pCmdReq->reqParams.verifyFinal.pSignature,
                &(pCmdRsp->rspParams.verifyFinal.signatureValid)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_DIGEST__
    case SMP_CC_SIGN_DIGEST                              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, signDigest,
                pCmdReq->reqParams.signDigest.moduleHandle,
                pCmdReq->reqParams.signDigest.tokenHandle,
                pCmdReq->reqParams.signDigest.keyHandle,
                pCmdReq->reqParams.signDigest.pDigest,
                pCmdReq->reqParams.signDigest.type,
                pCmdReq->reqParams.signDigest.pSignatureAttributes,
                &(pCmdRsp->rspParams.signDigest.pSignature)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_BUFFER__
    case SMP_CC_SIGN_BUFFER                              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, signBuffer,
                pCmdReq->reqParams.signBuffer.moduleHandle,
                pCmdReq->reqParams.signBuffer.tokenHandle,
                pCmdReq->reqParams.signBuffer.keyHandle,
                pCmdReq->reqParams.signBuffer.pDigest,
                pCmdReq->reqParams.signBuffer.type,
                pCmdReq->reqParams.signBuffer.pSignatureAttributes,
                &(pCmdRsp->rspParams.signBuffer.pSignature)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_INIT__
    case SMP_CC_SIGN_INIT                                :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, signInit,
                pCmdReq->reqParams.signInit.moduleHandle,
                pCmdReq->reqParams.signInit.tokenHandle,
                pCmdReq->reqParams.signInit.keyHandle,
                pCmdReq->reqParams.signInit.type,
                pCmdReq->reqParams.signInit.pSignatureAttributes,
                &(pCmdRsp->rspParams.signInit.opContext)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_UPDATE__
    case SMP_CC_SIGN_UPDATE                              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, signUpdate,
                pCmdReq->reqParams.signUpdate.moduleHandle,
                pCmdReq->reqParams.signUpdate.tokenHandle,
                pCmdReq->reqParams.signUpdate.keyHandle,
                pCmdReq->reqParams.signUpdate.pBuffer,
                pCmdReq->reqParams.signUpdate.opContext
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_FINAL__
    case SMP_CC_SIGN_FINAL                               :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, signFinal,
                pCmdReq->reqParams.signFinal.moduleHandle,
                pCmdReq->reqParams.signFinal.tokenHandle,
                pCmdReq->reqParams.signFinal.keyHandle,
                pCmdReq->reqParams.signFinal.opContext,
                &(pCmdRsp->rspParams.signFinal.pSignature)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_SIGNATURE_BUFFER__
    case SMP_CC_FREE_SIGNATURE_BUFFER                    :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, freeSignatureBuffer,
                pCmdReq->reqParams.freeSignature.ppSignature
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT__
    case SMP_CC_ENCRYPT                                  :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, encrypt,
                pCmdReq->reqParams.encrypt.moduleHandle,
                pCmdReq->reqParams.encrypt.tokenHandle,
                pCmdReq->reqParams.encrypt.keyHandle,
                pCmdReq->reqParams.encrypt.pMechanism,
                pCmdReq->reqParams.encrypt.pBuffer,
                &(pCmdRsp->rspParams.encrypt.cipherBuffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_INIT__
    case SMP_CC_ENCRYPT_INIT                             :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, encryptInit,
                pCmdReq->reqParams.encryptInit.moduleHandle,
                pCmdReq->reqParams.encryptInit.tokenHandle,
                pCmdReq->reqParams.encryptInit.keyHandle,
                pCmdReq->reqParams.encryptInit.pMechanism,
                &(pCmdRsp->rspParams.encryptInit.opContext)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_UPDATE__
    case SMP_CC_ENCRYPT_UPDATE                           :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, encryptUpdate,
                pCmdReq->reqParams.encryptUpdate.moduleHandle,
                pCmdReq->reqParams.encryptUpdate.tokenHandle,
                pCmdReq->reqParams.encryptUpdate.keyHandle,
                pCmdReq->reqParams.encryptUpdate.pBuffer,
                pCmdReq->reqParams.encryptUpdate.opContext,
                &(pCmdRsp->rspParams.encryptUpdate.cipherBuffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_FINAL__
    case SMP_CC_ENCRYPT_FINAL                            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, encryptFinal,
                pCmdReq->reqParams.encryptFinal.moduleHandle,
                pCmdReq->reqParams.encryptFinal.tokenHandle,
                pCmdReq->reqParams.encryptFinal.keyHandle,
                pCmdReq->reqParams.encryptFinal.opContext,
                &(pCmdRsp->rspParams.encryptFinal.cipherBuffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT__
    case SMP_CC_DECRYPT                                  :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, decrypt,
                pCmdReq->reqParams.decrypt.moduleHandle,
                pCmdReq->reqParams.decrypt.tokenHandle,
                pCmdReq->reqParams.decrypt.keyHandle,
                pCmdReq->reqParams.decrypt.pMechanism,
                pCmdReq->reqParams.decrypt.pCipherBuffer,
                &(pCmdRsp->rspParams.decrypt.buffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_INIT__
    case SMP_CC_DECRYPT_INIT                             :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, decryptInit,
                pCmdReq->reqParams.decryptInit.moduleHandle,
                pCmdReq->reqParams.decryptInit.tokenHandle,
                pCmdReq->reqParams.decryptInit.keyHandle,
                pCmdReq->reqParams.decryptInit.pMechanism,
                &(pCmdRsp->rspParams.decryptInit.opContext)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_UPDATE__
    case SMP_CC_DECRYPT_UPDATE                           :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, decryptUpdate,
                pCmdReq->reqParams.decryptUpdate.moduleHandle,
                pCmdReq->reqParams.decryptUpdate.tokenHandle,
                pCmdReq->reqParams.decryptUpdate.keyHandle,
                pCmdReq->reqParams.decryptUpdate.pCipherBuffer,
                pCmdReq->reqParams.decryptUpdate.opContext,
                &(pCmdRsp->rspParams.decryptUpdate.buffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_FINAL__
    case SMP_CC_DECRYPT_FINAL                            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, decryptFinal,
                pCmdReq->reqParams.decryptFinal.moduleHandle,
                pCmdReq->reqParams.decryptFinal.tokenHandle,
                pCmdReq->reqParams.decryptFinal.keyHandle,
                pCmdReq->reqParams.decryptFinal.opContext,
                &(pCmdRsp->rspParams.decryptFinal.buffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST__
    case SMP_CC_DIGEST                                   :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, digest,
                pCmdReq->reqParams.digest.moduleHandle,
                pCmdReq->reqParams.digest.tokenHandle,
                pCmdReq->reqParams.digest.pMechanism,
                pCmdReq->reqParams.digest.pInputBuffer,
                &(pCmdRsp->rspParams.digest.buffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_INIT__
    case SMP_CC_DIGEST_INIT                              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, digestInit,
                pCmdReq->reqParams.digestInit.moduleHandle,
                pCmdReq->reqParams.digestInit.tokenHandle,
                pCmdReq->reqParams.digestInit.pMechanism,
                &(pCmdRsp->rspParams.digestInit.opContext)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_UPDATE__
    case SMP_CC_DIGEST_UPDATE                            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, digestUpdate,
                pCmdReq->reqParams.digestUpdate.moduleHandle,
                pCmdReq->reqParams.digestUpdate.tokenHandle,
                pCmdReq->reqParams.digestUpdate.pBuffer,
                pCmdReq->reqParams.digestUpdate.opContext
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_FINAL__
    case SMP_CC_DIGEST_FINAL                             :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, digestFinal,
                pCmdReq->reqParams.digestFinal.moduleHandle,
                pCmdReq->reqParams.digestFinal.tokenHandle,
                pCmdReq->reqParams.digestFinal.opContext,
                &(pCmdRsp->rspParams.digestFinal.buffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_RANDOM__
    case SMP_CC_GET_RANDOM                               :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getRandom,
                pCmdReq->reqParams.getRandom.moduleHandle,
                pCmdReq->reqParams.getRandom.tokenHandle,
                pCmdReq->reqParams.getRandom.pRngRequest,
                pCmdReq->reqParams.getRandom.bytesRequested,
                &(pCmdRsp->rspParams.getRandom.random)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_STIR_RANDOM__
    case SMP_CC_STIR_RANDOM                              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, stirRandom,
                pCmdReq->reqParams.stirRandom.moduleHandle,
                pCmdReq->reqParams.stirRandom.tokenHandle,
                pCmdReq->reqParams.stirRandom.pRngRequest
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TRUSTED_DATA__
    case SMP_CC_GET_TRUSTED_DATA                         :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getTrustedData,
                pCmdReq->reqParams.getTrustedData.moduleHandle,
                pCmdReq->reqParams.getTrustedData.tokenHandle,
                pCmdReq->reqParams.getTrustedData.trustedDataType,
                pCmdReq->reqParams.getTrustedData.pTrustedDataInfo,
                &(pCmdRsp->rspParams.getTrustedData.dataValue)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UPDATE_TRUSTED_DATA__
    case SMP_CC_UPDATE_TRUSTED_DATA                      :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, updateTrustedData,
                pCmdReq->reqParams.updateTrustedData.moduleHandle,
                pCmdReq->reqParams.updateTrustedData.tokenHandle,
                pCmdReq->reqParams.updateTrustedData.trustedDataType,
                pCmdReq->reqParams.updateTrustedData.pTrustedDataInfo,
                pCmdReq->reqParams.updateTrustedData.trustedDataOp,
                pCmdReq->reqParams.updateTrustedData.pDataValue,
                &(pCmdRsp->rspParams.updateTrustedData.updatedDataValue)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SEAL_WITH_TRUSTED_DATA__
    case SMP_CC_SEAL_WITH_TRUSTED_DATA                   :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, sealWithTrustedData,
                pCmdReq->reqParams.sealWithTrustedData.moduleHandle,
                pCmdReq->reqParams.sealWithTrustedData.tokenHandle,
                pCmdReq->reqParams.sealWithTrustedData.pRequestTemplate,
                pCmdReq->reqParams.sealWithTrustedData.pDataToSeal,
                &(pCmdRsp->rspParams.sealWithTrustedData.dataOut)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNSEAL_WITH_TRUSTED_DATA__
    case SMP_CC_UNSEAL_WITH_TRUSTED_DATA                 :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, unsealWithTrustedData,
                pCmdReq->reqParams.unsealWithTrustedData.moduleHandle,
                pCmdReq->reqParams.unsealWithTrustedData.tokenHandle,
                pCmdReq->reqParams.unsealWithTrustedData.pRequestTemplate,
                pCmdReq->reqParams.unsealWithTrustedData.pDataToUnseal,
                &(pCmdRsp->rspParams.unsealWithTrustedData.dataOut)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SET_POLICY_STORAGE__
    case SMP_CC_SET_POLICY_STORAGE                       :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, setPolicyStorage,
                pCmdReq->reqParams.setPolicyStorage.moduleHandle,
                pCmdReq->reqParams.setPolicyStorage.tokenHandle,
                pCmdReq->reqParams.setPolicyStorage.objectHandle,
                pCmdReq->reqParams.setPolicyStorage.pPolicyAttributes,
                pCmdReq->reqParams.setPolicyStorage.pOpAttributes,
                pCmdReq->reqParams.setPolicyStorage.pData
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_POLICY_STORAGE__
    case SMP_CC_GET_POLICY_STORAGE                       :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getPolicyStorage,
                pCmdReq->reqParams.getPolicyStorage.moduleHandle,
                pCmdReq->reqParams.getPolicyStorage.tokenHandle,
                pCmdReq->reqParams.getPolicyStorage.objectHandle,
                pCmdReq->reqParams.getPolicyStorage.pOpAttributes,
                &(pCmdRsp->rspParams.getPolicyStorage.data)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS__
    case SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getCertificateRequestValidationAttrs,
                pCmdReq->reqParams.getCertReqValAttrs.moduleHandle,
                pCmdReq->reqParams.getCertReqValAttrs.tokenHandle,
                pCmdReq->reqParams.getCertReqValAttrs.objectHandle,
                pCmdReq->reqParams.getCertReqValAttrs.pCSRattributes,
                &(pCmdRsp->rspParams.getCertReqValAttrs.blob)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNWRAP_KEY_VALIDATED_SECRET__
    case SMP_CC_UNWRAP_KEY_VALIDATED_SECRET              :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, unWrapKeyValidatedSecret,
                pCmdReq->reqParams.unwrapKeyValidatedSecret.moduleHandle,
                pCmdReq->reqParams.unwrapKeyValidatedSecret.tokenHandle,
                pCmdReq->reqParams.unwrapKeyValidatedSecret.objectHandle,
                pCmdReq->reqParams.unwrapKeyValidatedSecret.rtKeyHandle,
                pCmdReq->reqParams.unwrapKeyValidatedSecret.pBlob,
                &(pCmdRsp->rspParams.unwrapKeyValidatedSecret.secret)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SMP_GET_QUOTE__
    case SMP_CC_SMP_GET_QUOTE                            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getQuote,
                pCmdReq->reqParams.getQuote.moduleHandle,
                pCmdReq->reqParams.getQuote.tokenHandle,
                pCmdReq->reqParams.getQuote.objectHandle,
                pCmdReq->reqParams.getQuote.type,
                pCmdReq->reqParams.getQuote.pInfo,
                pCmdReq->reqParams.getQuote.pNonce,
                pCmdReq->reqParams.getQuote.pReserved,
                &(pCmdRsp->rspParams.getQuote.quoteData),
                &(pCmdRsp->rspParams.getQuote.pQuoteSignature)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_ASYMMETRIC_KEY__
    case SMP_CC_CREATE_ASYMMETRIC_KEY                    :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, createAsymmetricKey,
                pCmdReq->reqParams.createAsymmetricKey.moduleHandle,
                pCmdReq->reqParams.createAsymmetricKey.tokenHandle,
                pCmdReq->reqParams.createAsymmetricKey.objectId,
                pCmdReq->reqParams.createAsymmetricKey.pKeyAttributes,
                pCmdReq->reqParams.createAsymmetricKey.initFlag,
                &(pCmdRsp->rspParams.createAsymmetricKey.objectIdOut),
                &(pCmdRsp->rspParams.createAsymmetricKey.objectAttributes),
                &(pCmdRsp->rspParams.createAsymmetricKey.keyHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_PRIVATE_KEY__
    case SMP_CC_GET_PRIVATE_KEY_BLOB                           :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getPrivateKeyBlob,
                pCmdReq->reqParams.getPrivateKeyBlob.moduleHandle,
                pCmdReq->reqParams.getPrivateKeyBlob.tokenHandle,
                pCmdReq->reqParams.getPrivateKeyBlob.objectHandle,
                &(pCmdRsp->rspParams.getPrivateKeyBlob.privkeyBlob)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_PUBLIC_KEY__
    case SMP_CC_GET_PUBLIC_KEY                           :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getPublicKey,
                pCmdReq->reqParams.getPublicKey.moduleHandle,
                pCmdReq->reqParams.getPublicKey.tokenHandle,
                pCmdReq->reqParams.getPublicKey.objectHandle,
                &(pCmdRsp->rspParams.getPublicKey.pPublicKey)
        );
        break;
    case SMP_CC_GET_PUBLIC_KEY_BLOB                           :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getPublicKeyBlob,
                pCmdReq->reqParams.getPublicKeyBlob.moduleHandle,
                pCmdReq->reqParams.getPublicKeyBlob.tokenHandle,
                pCmdReq->reqParams.getPublicKeyBlob.objectHandle,
                &(pCmdRsp->rspParams.getPublicKeyBlob.pubkeyBlob)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DUPLICATEKEY__
    case SMP_CC_DUPLICATEKEY                           :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, DuplicateKey,
                pCmdReq->reqParams.duplicateKey.moduleHandle,
                pCmdReq->reqParams.duplicateKey.tokenHandle,
                pCmdReq->reqParams.duplicateKey.keyHandle,
                pCmdReq->reqParams.duplicateKey.pNewPubkey,
                &(pCmdRsp->rspParams.duplicateKey.duplicateBuf)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_IMPORTDUPLICATEKEY__
    case SMP_CC_IMPORTDUPLICATEKEY                           :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, ImportDuplicateKey,
                pCmdReq->reqParams.importDuplicateKey.moduleHandle,
                pCmdReq->reqParams.importDuplicateKey.tokenHandle,
                pCmdReq->reqParams.importDuplicateKey.pKeyAttributes,
                pCmdReq->reqParams.importDuplicateKey.pDuplicateBuf,
                &(pCmdRsp->rspParams.importDuplicateKey.objectAttributes),
                &(pCmdRsp->rspParams.importDuplicateKey.keyHandle)
        );
        break ;
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_PUBLIC_KEY__
    case SMP_CC_FREE_PUBLIC_KEY                          :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, freePublicKey,
                pCmdReq->reqParams.freePublicKey.ppPublicKey
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_SYMMETRIC_KEY__
    case SMP_CC_CREATE_SYMMETRIC_KEY                     :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, createSymmetricKey,
                pCmdReq->reqParams.createSymmetricKey.moduleHandle,
                pCmdReq->reqParams.createSymmetricKey.tokenHandle,
                pCmdReq->reqParams.createSymmetricKey.objectId,
                pCmdReq->reqParams.createSymmetricKey.pAttributeKey,
                pCmdReq->reqParams.createSymmetricKey.initFlag,
                &(pCmdRsp->rspParams.createSymmetricKey.objectIdOut),
                &(pCmdRsp->rspParams.createSymmetricKey.objectAttributes),
                &(pCmdRsp->rspParams.createSymmetricKey.keyHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_IMPORT_EXTERNAL_KEY__
    case SMP_CC_IMPORT_EXTERNAL_KEY                     :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, importExternalKey,
                pCmdReq->reqParams.createObject.moduleHandle,
                pCmdReq->reqParams.createObject.tokenHandle,
                pCmdReq->reqParams.createObject.objectIdIn,
                pCmdReq->reqParams.createObject.pObjectAttributes,
                &(pCmdRsp->rspParams.createObject.objectIdOut),
                &(pCmdRsp->rspParams.createObject.objectAttributesOut),
                &(pCmdRsp->rspParams.createObject.handle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_EXPORT_OBJECT__
    case SMP_CC_EXPORT_OBJECT                            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, exportObject,
                pCmdReq->reqParams.exportObject.moduleHandle,
                pCmdReq->reqParams.exportObject.tokenHandle,
                pCmdReq->reqParams.exportObject.objectHandle,
                &(pCmdRsp->rspParams.exportObject.exportedObject)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SERIALIZE_OBJECT__
    case SMP_CC_SERIALIZE_OBJECT                         :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, serializeObject,
                pCmdReq->reqParams.serializeObject.moduleHandle,
                pCmdReq->reqParams.serializeObject.tokenHandle,
                pCmdReq->reqParams.serializeObject.objectId,
                &(pCmdRsp->rspParams.serializeObject.serializedObject)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_OBJECT__
    case SMP_CC_CREATE_OBJECT                            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, createObject,
                pCmdReq->reqParams.createObject.moduleHandle,
                pCmdReq->reqParams.createObject.tokenHandle,
                pCmdReq->reqParams.createObject.objectIdIn,
                pCmdReq->reqParams.createObject.pObjectAttributes,
                &(pCmdRsp->rspParams.createObject.objectAttributesOut),
                &(pCmdRsp->rspParams.createObject.objectIdOut),
                &(pCmdRsp->rspParams.createObject.handle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DELETE_OBJECT__
    case SMP_CC_DELETE_OBJECT                            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, deleteObject,
                pCmdReq->reqParams.deleteObject.moduleHandle,
                pCmdReq->reqParams.deleteObject.tokenHandle,
                pCmdReq->reqParams.deleteObject.objectHandle,
                pCmdReq->reqParams.deleteObject.authContext
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE__
    case SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE            :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getRootOfTrustCertificate,
                pCmdReq->reqParams.getRootOfTrustCertificate.moduleHandle,
                pCmdReq->reqParams.getRootOfTrustCertificate.objectId,
                pCmdReq->reqParams.getRootOfTrustCertificate.type,
                &(pCmdRsp->rspParams.getRootOfTrustCertificate.certificate)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE__
    case SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE             :
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getRootOfTrustKeyHandle,
                pCmdReq->reqParams.getRootOfTrustKeyHandle.moduleHandle,
                pCmdReq->reqParams.getRootOfTrustKeyHandle.objectId,
                pCmdReq->reqParams.getRootOfTrustKeyHandle.type,
                &(pCmdRsp->rspParams.getRootOfTrustKeyHandle.keyHandle)
        );
        break;
#endif
#ifdef __SMP_ENABLE_SMP_CC_GET_LAST_ERROR__
    case SMP_CC_GET_LAST_ERROR:
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getLastError,
                pCmdReq->reqParams.getLastError.moduleHandle,
                pCmdReq->reqParams.getLastError.tokenHandle,
                pCmdReq->reqParams.getLastError.objectHandle,
                &(pCmdRsp->rspParams.getLastError.errorAttributes)
        );
        break;
#endif
#ifdef __SMP_ENABLE_SMP_CC_SELF_TEST__
    case SMP_CC_SELF_TEST:
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, selfTest,
                pCmdReq->reqParams.selfTest.moduleHandle,
                pCmdReq->reqParams.selfTest.pTestRequest,
                &(pCmdRsp->rspParams.selfTest.testResponse)
        );
        break;
#endif
#ifdef __SMP_ENABLE_SMP_CC_SELF_TEST_POLL__
    case SMP_CC_SELF_TEST_POLL:
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, selfTestPoll,
                pCmdReq->reqParams.selfTestPoll.moduleHandle,
                pCmdReq->reqParams.selfTestPoll.pTestRequest,
                pCmdReq->reqParams.selfTestPoll.testContext,
                &(pCmdRsp->rspParams.selfTest.testResponse)
        );
        break;
#endif
#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_CAPABILITY__
    case SMP_CC_GET_MODULE_CAPABILITY:
        pCmdRsp->returnCode = CALL_SMP_API(TPM2, getCapability,
            pCmdReq->reqParams.getModuleCapability.moduleId,
            pCmdReq->reqParams.getModuleCapability.pCapabilitySelectRange,
            &(pCmdRsp->rspParams.getModuleCapability.moduleCapabilities)
        );
        break;
#endif
    default:
        status = ERR_NOT_IMPLEMENTED;
        DB_PRINT("%s.%d Invalid Command code received- %d\n",
                __FUNCTION__, __LINE__, cmdCode);
        goto exit;
        break;
    }
exit:
    return status;
}

#endif /* #if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TPM2__)) */
