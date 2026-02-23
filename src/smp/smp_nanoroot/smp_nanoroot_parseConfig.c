/*
 * smp_nanoroot_parseConfig.c
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

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_NANOROOT__))

#include <stdio.h>
#include <string.h>
#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mocana.h"
#include "common/mdefs.h"
#include "common/mstdlib.h"
#include "common/mjson.h"
#include "common/mrtos.h"
#include "common/mfmgmt.h"
#include "common/mstdlib.h"
#include "common/debug_console.h"
#include "smp_nanoroot_device_protect.h"
#include "smp_nanoroot_parseConfig.h"

#define NanoROOT_ATTRIBUTES "attributes"
#define NanoROOT_ATTRIBUTE_NAME "attribute_name"
#define NanoROOT_ATTRIBUTE_NAMES "attribute_names"
#define NanoROOT_ATTRIBUTE_VALUE "attribute_value"
#define NanoROOT_ATTRIBUTE_TYPE "type"
#define NanoROOT_ATTRIBUTE_PATH "path"
#define NanoROOT_ATTRIBUTE_VAR_NAME "variable_name"
#define NanoROOT_ATTRIBUTE_OUTPUT_FORMAT "output_format"
#define NanoROOT_ATTRIBUTE_ARGUMENT "argument"

#define NanoROOT_ATTRIBUTE_TYPE_ENV "ENV"
#define NanoROOT_ATTRIBUTE_TYPE_PROGRAM "program"

#define NanoROOT_ATTRIBUTE_OUTPUT_FORMAT_JSON "JSON"

/* Allowlist of permitted script directories.
 * To override, define NANOROOT_SCRIPT_DIRS as a comma-separated list of quoted paths, e.g.:
 *   -DNANOROOT_SCRIPT_DIRS='"/etc/digicert/", "/opt/scripts/"'
 */
#ifndef NANOROOT_SCRIPT_DIRS
#define NANOROOT_SCRIPT_DIRS "/etc/digicert/"
#endif
static const char* gAllowedScriptDirs[] = {
    NANOROOT_SCRIPT_DIRS,
#ifdef MANDATORY_BASE_PATH
    MANDATORY_BASE_PATH,
#endif
    NULL
};


/* Structure for parsing customer provided attributes */
typedef enum
{
    ATTRIBUTE_TYPE_NONE = 0,
    ATTRIBUTE_TYPE_ENV,
    ATTRIBUTE_TYPE_PROGRAM
} AttributeType;

typedef enum
{
    ATTRIBUTE_OUTPUT_NONE = 0,
    ATTRIBUTE_OUTPUT_JSON,
    ATTRIBUTE_OUTPUT_STRING
} AttributeOutput;

typedef struct
{
    sbyte *pName;
    sbyte *pOutput;
    ubyte4 outputLen;
} Attr;

typedef struct
{
    Attr *pAttr;
    ubyte4 attrCount;
    AttributeType type;
    sbyte *pEnv;
    sbyte *pPath;
    sbyte *pArg;
    AttributeOutput output;
} AttributeItem;

typedef struct
{
    AttributeItem *pItems;
    ubyte4 itemCount;
} AttributeList;

extern NROOTKdfElement *gpElementList;
extern ubyte gNROOTKdfEleCount;

static MSTATUS NanoROOT_agentDeleteAttributeList(AttributeList **ppAttrList)
{
    MSTATUS status = OK, fstatus;
    ubyte4 i, j;

    if (NULL != ppAttrList && NULL != *ppAttrList)
    {
        for (i = 0; i < (*ppAttrList)->itemCount; i++)
        {
            for (j = 0; j < (*ppAttrList)->pItems[i].attrCount; j++)
            {
                DB_PRINT("\t\tAttribute name : %s\n", (*ppAttrList)->pItems[i].pAttr[j].pName);
                fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].pAttr[j].pName));
                if (OK == status)
                    status = fstatus;

                fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].pAttr[j].pOutput));
                if (OK == status)
                    status = fstatus;
            }

            fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].pAttr));
            if (OK == status)
                status = fstatus;

            if (NULL != (*ppAttrList)->pItems[i].pEnv)
            {
                fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].pEnv));
                if (OK == status)
                    status = fstatus;
            }

            if (NULL != (*ppAttrList)->pItems[i].pPath)
            {
                fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].pPath));
                if (OK == status)
                    status = fstatus;
            }

            if (NULL != (*ppAttrList)->pItems[i].pArg)
            {
                fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].pArg));
                if (OK == status)
                    status = fstatus;
            }
        }

        fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) ppAttrList);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

static MSTATUS NanoROOT_agentParseAttributes(ubyte *pAttributeFile, AttributeList **ppAttrList)
{
    MSTATUS status;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens = 0;
    ubyte4 len = 0;
    ubyte4 index, objIndex, i, j;
    JSON_TokenType token = {0}, objToken = {0}, nameToken = {0};
    AttributeList *pAttrList = NULL;
    sbyte *pTemp = NULL;
    ubyte expectedType;

    if(NULL == pAttributeFile || NULL == ppAttrList)
    {
        DB_PRINT("%s:%d Error: NULL attribute name\n", __func__, __LINE__);
        return ERR_NULL_POINTER;
    }

    status = DIGICERT_readFile((const char *)pAttributeFile, &pData, &dataLen);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

    /* Parse JSON */
    status = JSON_parse(pJCtx, (const sbyte *)pData, dataLen, &numTokens);
    if (OK != status)
    {
        goto exit;
    }

    /* Get array of attributes */
    status = JSON_getJsonArrayValue(
        pJCtx, 0, (sbyte*)NanoROOT_ATTRIBUTES, &index, &token, TRUE);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pAttrList, 1, sizeof(AttributeList));
    if (OK != status)
    {
        goto exit;
    }

    pAttrList->itemCount = token.elemCnt;

    status = DIGI_CALLOC((void **) &pAttrList->pItems, token.elemCnt, sizeof(AttributeItem));
    if (OK != status)
    {
        goto exit;
    }

    /* Loop through array of attributes */
    for (i = 0; i < token.elemCnt; i++)
    {
        index++;

        expectedType = JSON_String;
        status = JSON_getObjectIndex(
            pJCtx, (sbyte*)NanoROOT_ATTRIBUTE_NAME, index, &objIndex, TRUE);
        if (OK != status)
        {
            expectedType = JSON_Array;
            status = JSON_getObjectIndex(
                pJCtx, (sbyte*)NanoROOT_ATTRIBUTE_NAMES, index, &objIndex, TRUE);
            if (OK != status)
            {
                goto exit;
            }
        }

        objIndex++;
        status = JSON_getToken(pJCtx, objIndex, &objToken);
        if (OK != status)
        {
            goto exit;
        }

        if (objToken.type != expectedType)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            goto exit;
        }

        /* Get attribute name, could be a string or array value */
        if (JSON_Array == objToken.type)
        {
            /* Attribute name is array, loop through each element and store it */
            status = DIGI_CALLOC(
                (void **) &(pAttrList->pItems[i].pAttr),
                objToken.elemCnt, sizeof(Attr));
            if (OK != status)
            {
                goto exit;
            }

            for (j = 0; j < objToken.elemCnt; j++)
            {
                objIndex++;

                status = JSON_getToken(pJCtx, objIndex, &nameToken);
                if (OK != status)
                {
                    goto exit;
                }

                if (JSON_String != nameToken.type)
                {
                    status = ERR_JSON_UNEXPECTED_TYPE;
                    goto exit;
                }

                if (nameToken.len >= NanoROOT_MAX_VALUE_LEN)
                {
                    status = ERR_BAD_LENGTH;
                    DB_PRINT("%s:%d Error: Attribute length %d exceeds maximum %d\n",
                            __func__, __LINE__, nameToken.len, NanoROOT_MAX_VALUE_LEN - 1);
                    goto exit;
                }

                status = DIGI_MALLOC_MEMCPY(
                    (void **) &(pAttrList->pItems[i].pAttr[j].pName),
                    nameToken.len + 1, (void *) nameToken.pStart, nameToken.len);
                if (OK != status)
                {
                    goto exit;
                }
                pAttrList->pItems[i].pAttr[j].pName[nameToken.len] = '\0';

                pAttrList->pItems[i].attrCount++;
                DB_PRINT("%s.%d Attribute name : %s Attribute name length:%d \n", __func__, __LINE__,
                    pAttrList->pItems[i].pAttr[j].pName, nameToken.len);
            }

            DIGI_FREE((void **) &pTemp);
            status = JSON_getJsonStringValue(
                pJCtx, index, (sbyte*)NanoROOT_ATTRIBUTE_OUTPUT_FORMAT, &pTemp, TRUE);
            if (OK != status)
            {
                goto exit;
            }

            if (0 == DIGI_STRCMP(pTemp, (sbyte*)NanoROOT_ATTRIBUTE_OUTPUT_FORMAT_JSON))
            {
                pAttrList->pItems[i].output = ATTRIBUTE_OUTPUT_JSON;
                DB_PRINT("%s.%d Attribute name : %s output_format : json\n",
                    __func__, __LINE__, pAttrList->pItems[i].pAttr[0].pName);
            }
            else
            {
                DB_PRINT("%s.%d Attribute name : %s output_format : string\n",
                    __func__, __LINE__, pAttrList->pItems[i].pAttr[0].pName);
            }
        }
        else if (JSON_String == objToken.type)
        {
            if (objToken.len >= NanoROOT_MAX_VALUE_LEN)
            {
                status = ERR_BAD_LENGTH;
                DB_PRINT("%s:%d Error: Attribute length %d exceeds maximum %d\n",
                        __func__, __LINE__, objToken.len, NanoROOT_MAX_VALUE_LEN - 1);
                goto exit;
            }

            /* Attribute name is string, store single value */
            status = DIGI_CALLOC(
                (void **) &(pAttrList->pItems[i].pAttr), 1, sizeof(Attr));
            if (OK != status)
            {
                goto exit;
            }

            status = DIGI_MALLOC_MEMCPY(
                (void **) &(pAttrList->pItems[i].pAttr[0].pName),
                objToken.len + 1, (void *) objToken.pStart, objToken.len);
            if (OK != status)
            {
                goto exit;
            }
            pAttrList->pItems[i].pAttr[0].pName[objToken.len] = '\0';

            pAttrList->pItems[i].attrCount = 1;

            /* Assume string format */
            pAttrList->pItems[i].output = ATTRIBUTE_OUTPUT_STRING;
            DB_PRINT("%s.%d Attribute name : %s Attribute name length:%d output_format : string\n",
            __func__, __LINE__, pAttrList->pItems[i].pAttr[0].pName, objToken.len);
        }

        /* Get attribute type */
        DIGI_FREE((void **) &pTemp);
        status = JSON_getJsonStringValue(
            pJCtx, index, (sbyte*)NanoROOT_ATTRIBUTE_TYPE, &pTemp, TRUE);
        if (OK != status)
        {
            goto exit;
        }

        if (0 == DIGI_STRCMP(pTemp, (sbyte*)NanoROOT_ATTRIBUTE_TYPE_ENV))
        {
            /* Assign type */
            pAttrList->pItems[i].type = ATTRIBUTE_TYPE_ENV;

            /* Assign environment variable name */
            DIGI_FREE((void **) &pTemp);
            status = JSON_getJsonStringValue(
                pJCtx, index, (sbyte*)NanoROOT_ATTRIBUTE_VAR_NAME, &pTemp, TRUE);
            if (OK != status)
            {
                goto exit;
            }
            len = DIGI_STRLEN(pTemp);
            if (len >= NanoROOT_MAX_VALUE_LEN)
            {
                status = ERR_BAD_LENGTH;
                DB_PRINT("%s:%d Error: Attribute length %d exceeds maximum %d\n",
                        __func__, __LINE__, len, NanoROOT_MAX_VALUE_LEN - 1);
                goto exit;
            }

            pAttrList->pItems[i].pEnv = pTemp; pTemp = NULL;
            DB_PRINT("%s.%d Attribute name : %s type :env env_var:%s\n", 
            __func__, __LINE__, pAttrList->pItems[i].pAttr[0].pName, pAttrList->pItems[i].pEnv);
        }
        else if (0 == DIGI_STRCMP(pTemp, (sbyte*)NanoROOT_ATTRIBUTE_TYPE_PROGRAM))
        {
            /* Assign type */
            pAttrList->pItems[i].type = ATTRIBUTE_TYPE_PROGRAM;

            /* Assign path */
            DIGI_FREE((void **) &pTemp);
            status = JSON_getJsonStringValue(
                pJCtx, index, (sbyte*)NanoROOT_ATTRIBUTE_PATH, &pTemp, TRUE);
            if (OK != status)
            {
                goto exit;
            }

            len = DIGI_STRLEN(pTemp);
            if (len >= NanoROOT_MAX_VALUE_LEN)
            {
                status = ERR_BAD_LENGTH;
                DB_PRINT("%s:%d Error: Program length %d exceeds maximum %d\n",
                        __func__, __LINE__, len, NanoROOT_MAX_VALUE_LEN - 1);
                goto exit;
            }

            pAttrList->pItems[i].pPath = pTemp; pTemp = NULL;

            /* Assign optional argument */
            DIGI_FREE((void **) &pTemp);
            status = JSON_getJsonStringValue(
                pJCtx, index, (sbyte*)NanoROOT_ATTRIBUTE_ARGUMENT, &pTemp, TRUE);
            if (OK == status)
            {
                len = DIGI_STRLEN(pTemp);
                if (len >= NanoROOT_MAX_VALUE_LEN)
                {
                    status = ERR_BAD_LENGTH;
                    DB_PRINT("%s:%d Error: Argument length %d exceeds maximum %d\n",
                            __func__, __LINE__, len, NanoROOT_MAX_VALUE_LEN - 1);
                    goto exit;
                }
                pAttrList->pItems[i].pArg = pTemp; pTemp = NULL;
            }
            DB_PRINT("%s.%d Attribute name : %s type :program path : %s arg : %s arg_len:%d\n",
            __func__, __LINE__, pAttrList->pItems[i].pAttr[0].pName,
            pAttrList->pItems[i].pPath, pAttrList->pItems[i].pArg, len);

            if (FALSE == FMGMT_pathExists((const sbyte *)pAttrList->pItems[i].pPath, NULL))
            {
                DB_PRINT("%s.%d: Error credfile %s does not exist.\n",__FUNCTION__, __LINE__, pAttrList->pItems[i].pPath);
                status = ERR_FILE_BAD_DATA;
                goto exit;
            }

        }

        /* Move to next object */
        status = JSON_getLastIndexInObject(pJCtx, index, &index);
        if (OK != status)
        {
            goto exit;
        }
    }

    *ppAttrList = pAttrList; pAttrList = NULL;

exit:

    if (NULL != pAttrList)
    {
        NanoROOT_agentDeleteAttributeList(&pAttrList);
    }

    DIGI_FREE((void **) &pTemp);
    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }
    DIGI_FREE((void **) &pData);

    return status;
}

MSTATUS NanoROOT_validateInput(const sbyte *pInput, const sbyte *pAllowed)
{
    ubyte4 i, len, blocked_chars_len, allowed_chars_len;
    
    if (NULL == pInput)
    {
        return ERR_NULL_POINTER;
    }
    
    len = DIGI_STRLEN(pInput);
    if (0 == len)
    {
        return ERR_INVALID_ARG;
    }
    blocked_chars_len = DIGI_STRLEN((sbyte *)NANOROOT_BLOCKED_CHARS);
    
    /* Check for dangerous characters (blocklist) */
    for (i = 0; i < len; i++)
    {
        if (NULL != DIGI_STRCHR((sbyte *)NANOROOT_BLOCKED_CHARS, pInput[i], blocked_chars_len))
        {
            DB_PRINT("%s:%d Error: Dangerous character '%c' found in input\n",
                     __func__, __LINE__, pInput[i]);
            return ERR_INVALID_ARG;
        }
    }
    
    /* Check against allowlist if provided */
    if (NULL != pAllowed)
    {
        allowed_chars_len = DIGI_STRLEN(pAllowed);
        for (i = 0; i < len; i++)
        {
            if (NULL == DIGI_STRCHR((sbyte *)pAllowed, pInput[i], allowed_chars_len))
            {
                DB_PRINT("%s:%d Error: Invalid character '%c' in input\n",
                         __func__, __LINE__, pInput[i]);
                return ERR_INVALID_ARG;
            }
        }
    }
    
    return OK;
}

MSTATUS NanoROOT_validatePath(const sbyte *pPath)
{
    MSTATUS status = ERR_INVALID_ARG;
    sbyte realPath[PATH_MAX];
    const sbyte **ppDir;
    ubyte4 dirLen;
    
    if (NULL == pPath)
    {
        return ERR_NULL_POINTER;
    }
    
    /* Reject relative paths */
    if ('/' != pPath[0])
    {
        DB_PRINT("%s:%d Error: Relative path not allowed: %s\n",
                 __func__, __LINE__, pPath);
        return ERR_INVALID_ARG;
    }
    
    /* Reject path traversal attempts */
    if (NULL != strstr((const char *)pPath, ".."))
    {
        DB_PRINT("%s:%d Error: Path traversal detected: %s\n",
                 __func__, __LINE__, pPath);
        return ERR_FILE_BAD_DATA;
    }
    
    /*
     * Defensive check: Ensure FMGMT_getFullPath does not overflow realPath.
     * Assumes FMGMT_getFullPath writes at most (PATH_MAX - 1) characters and null-terminates realPath.
     * If this is not guaranteed, this code must be updated to prevent buffer overflow.
     */
    status = FMGMT_getFullPath(pPath, realPath, PATH_MAX);
    if (OK > status)
    {
         DB_PRINT("%s:%d Error: FMGMT_getFullPath() failed\n", __func__, __LINE__);
        return ERR_FILE_BAD_DATA;
    }
    /* Defensive: Ensure realPath is null-terminated and not too long */
    if (DIGI_STRLEN(realPath) == PATH_MAX) {
        DB_PRINT("%s:%d Error: realPath not null-terminated or too long\n", __func__, __LINE__);
        return ERR_FILE_BAD_DATA;
    }

    status = ERR_FILE_BAD_DATA;
    /* Check path is within allowed directories */
    for (ppDir = (const sbyte **)gAllowedScriptDirs; *ppDir != NULL; ppDir++)
    {
        dirLen = DIGI_STRLEN((sbyte *)*ppDir);
        if (0 == DIGI_STRNCMP(realPath, (sbyte *)*ppDir, dirLen))
        {
            status = OK;
            break;
        }
    }
    
    if (OK != status)
    {
        {
            DB_PRINT("%s:%d Error: Path not in allowed directory: %s\n",
                     __func__, __LINE__, realPath);
            return ERR_FILE_BAD_DATA;
        }
    }
    
    return OK;
}

static MSTATUS NanoROOT_agentExecuteScript(sbyte *pPath, sbyte *pArg, sbyte **ppOutput)
{
    MSTATUS status = OK;

    /* Validate path */
    status = NanoROOT_validatePath(pPath);
    if (OK != status)
    {
        DB_PRINT("%s:%d Error: Invalid characters in path\n", __func__, __LINE__);
        goto exit;
    }
    
    /* Validate path characters */
    status = NanoROOT_validateInput(pPath, (sbyte *)NANOROOT_ALLOWED_PATH_CHARS);
    if (OK != status)
    {
        DB_PRINT("%s:%d Error: Invalid characters in path\n", __func__, __LINE__);
        goto exit;
    }
    
    /* Validate argument if provided */
    if (NULL != pArg)
    {
        status = NanoROOT_validateInput(pArg, (sbyte *)NANOROOT_ALLOWED_ARG_CHARS);
        if (OK != status)
        {
            DB_PRINT("%s:%d Error: Invalid characters in argument\n", __func__, __LINE__);
            goto exit;
        }
    }

    DB_PRINT("pPath : %s\n", pPath);
    DB_PRINT("pArg : %s\n", pArg);
    status = RTOS_processExecuteWithArg(pPath, pArg, ppOutput);
    if (OK != status)
    {
        DB_PRINT("%s:%d Error: RTOS_processExecuteWithArg() failed, status=%d\n", __func__, __LINE__, status);
        if (NULL != ppOutput && NULL != *ppOutput)
        {
            DB_PRINT("Process output/error: %s\n", *ppOutput);
        }
        goto exit;
    }
    else
    {
        DB_PRINT("Process succeeded, output: %s\n", (ppOutput && *ppOutput) ? (char*)*ppOutput : "(null)");
    }

exit:

    return status;
}

static MSTATUS NanoROOT_agentProcessAttribute(Attr *pAttr, AttributeItem *pAttrItem)
{
    MSTATUS status = OK;
    sbyte *pOutput = NULL;
    ubyte4 outputLen = 0;
    ubyte4 numTokens;
    JSON_ContextType *pJCtx = NULL;
    sbyte *pResult = NULL;

    if(NULL == pAttr || NULL == pAttrItem)
    {
        DB_PRINT("%s:%d Error: NULL attribute name\n", __func__, __LINE__);
        return ERR_NULL_POINTER;
    }

    if (ATTRIBUTE_TYPE_ENV == pAttrItem->type)
    {
        status = FMGMT_getEnvironmentVariableValueAlloc(
            pAttrItem->pEnv, (sbyte **) &pOutput);
        if (OK != status)
        {
            goto exit;
        }
        outputLen = DIGI_STRLEN(pOutput);
    }
    else if (ATTRIBUTE_TYPE_PROGRAM == pAttrItem->type)
    {
        status = NanoROOT_agentExecuteScript(
            pAttrItem->pPath,
            pAttrItem->pArg,
            (sbyte **) &pOutput);
        if (OK != status)
        {
            DB_PRINT("%s:%d Error: NanoROOT_agentExecuteScript() failed\n", __func__, __LINE__);
            goto exit;
        }
        outputLen = DIGI_STRLEN(pOutput);
    }

    if (NULL != pOutput)
    {
        if (ATTRIBUTE_OUTPUT_JSON == pAttrItem->output)
        {
            status = JSON_acquireContext(&pJCtx);
            if (OK != status)
            {
                goto exit;
            }

            status = JSON_parse(pJCtx, pOutput, outputLen, &numTokens);
            if (OK != status)
            {
                goto exit;
            }

            status = JSON_getJsonStringValue(
                pJCtx, 0, pAttr->pName, &pResult, TRUE);
            if (OK != status)
            {
                goto exit;
            }
            pAttr->pOutput = pResult;
            pAttr->outputLen = DIGI_STRLEN(pResult);
            DIGI_FREE((void **) &pOutput);
        }
        else if (ATTRIBUTE_OUTPUT_STRING == pAttrItem->output)
        {
            pAttr->pOutput = pOutput;
            pAttr->outputLen = outputLen;
        }
        else
        {
            status = ERR_FILE_BAD_DATA;
            goto exit;
        }
    }
    pResult = NULL;
    pOutput = NULL;

    DB_PRINT("%s.%d attribute name : %s path : %s arg : %s output : %s\n",
        __func__, __LINE__, pAttr->pName, pAttrItem->pPath, pAttrItem->pArg, pAttr->pOutput);

exit:

    if (NULL != pResult)
    {
        DIGI_FREE((void **) &pResult);
    }

    if (NULL != pOutput)
    {
        DIGI_FREE((void **) &pOutput);
    }

    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }

    return status;
}

static MSTATUS NanoROOT_createFingerPrintData(AttributeList *pAttrList, ubyte4 attrCount)
{
    MSTATUS status = OK;
    AttributeItem *pAttrItem = NULL;
    ubyte4 i, j, k = 0;
    ubyte4 labelLen, valueLen;

    status = DIGI_CALLOC((void **) &gpElementList, attrCount, sizeof(NROOTKdfElement));
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < pAttrList->itemCount; i++)
    {
       for (j = 0; j < pAttrList->pItems[i].attrCount; j++)
       {
            pAttrItem = &pAttrList->pItems[i];

            if (NULL == pAttrItem->pAttr[j].pName)
            {
                status = ERR_NULL_POINTER;
                DB_PRINT("%s:%d Error: NULL attribute name\n", __func__, __LINE__);
                goto exit;
            }

            labelLen = DIGI_STRLEN(pAttrItem->pAttr[j].pName);
            if (labelLen >= NanoROOT_MAX_LABEL_LEN)
            {
                status = ERR_BAD_LENGTH;
                DB_PRINT("%s:%d Error: Label length %d exceeds maximum %d\n",
                        __func__, __LINE__, labelLen, NanoROOT_MAX_LABEL_LEN - 1);
                goto exit;
            }

            if (NULL == pAttrItem->pAttr[j].pOutput)
            {
                status = ERR_NULL_POINTER;
                DB_PRINT("%s:%d Error: NULL attribute output\n", __func__, __LINE__);
                goto exit;
            }

            valueLen = DIGI_STRLEN(pAttrItem->pAttr[j].pOutput);
            if (valueLen >= NanoROOT_MAX_VALUE_LEN)
            {
                status = ERR_BAD_LENGTH;
                DB_PRINT("%s:%d Error: Value length %d exceeds maximum %d\n",
                        __func__, __LINE__, valueLen, NanoROOT_MAX_VALUE_LEN - 1);
                goto exit;
            }

            DB_PRINT("%s:%d name:%s value:%s labelLen:%d valueLen:%d\n", __func__, __LINE__,
                pAttrItem->pAttr[j].pName, pAttrItem->pAttr[j].pOutput, labelLen, valueLen);

            gpElementList[k].labelLen = labelLen;
            DIGI_MEMCPY(gpElementList[k].pLabel, pAttrItem->pAttr[j].pName, labelLen);
            gpElementList[k].pLabel[labelLen] = '\0';

            gpElementList[k].valueLen = valueLen;
            DIGI_MEMCPY(gpElementList[k].pValue, pAttrItem->pAttr[j].pOutput, valueLen);
            gpElementList[k].pValue[valueLen] = '\0';

            k++;
       }
    }

exit:
    if (OK != status && NULL != gpElementList)
    {
        DIGI_FREE((void **)&gpElementList);
    }

    return status;
}

MSTATUS NanoROOT_parseCredFile(ubyte *pAttributeFile)
{
    MSTATUS status;
    AttributeList *pAttrList = NULL;
    AttributeItem *pAttrItem = NULL;
    ubyte4 i, j;
    ubyte attrCount = 0;

    status = NanoROOT_agentParseAttributes(
        pAttributeFile, &pAttrList);
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < pAttrList->itemCount; i++)
    {
       for (j = 0; j < pAttrList->pItems[i].attrCount; j++)
       {
            pAttrItem = &pAttrList->pItems[i];
            status = NanoROOT_agentProcessAttribute(&pAttrList->pItems[i].pAttr[j], pAttrItem);
            if (OK != status)
            {
                goto exit;
            }
            attrCount++;
       }
    }
    DB_PRINT("%s:%d AttrCount:%d\n", __func__, __LINE__, attrCount);

    status = NanoROOT_createFingerPrintData(pAttrList, attrCount);
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < attrCount; i++)
    {
        DB_PRINT("%s:%d Label:%s  labelLen:%d value:%s valueLen:%d \n", __func__, __LINE__,
            gpElementList[i].pLabel, gpElementList[i].labelLen, gpElementList[i].pValue, gpElementList[i].valueLen);
    }

    gNROOTKdfEleCount = attrCount;

exit:

    if (NULL != pAttrList)
    {
        NanoROOT_agentDeleteAttributeList(&pAttrList);
    }

    return status;
}

#endif /* #if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_NANOROOT__)) */
