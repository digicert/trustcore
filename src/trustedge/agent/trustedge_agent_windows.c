/* trustedge_agent_windows.c
 *
 * Windows specific functionality for update packages
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
 *
 */

#if defined(__RTOS_WIN32__)

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <msi.h>
#include <msiquery.h>
#include "../../common/msg_logger.h"
#include "../../common/common_utils.h"
#include "../../trustedge/utils/trustedge_utils.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../trustedge/agent/trustedge_agent_updatepolicy.h"

#pragma comment(lib, "msi.lib")

#define ARTIFACTS_DIR "artifacts"
#define TRUSTEDGE_UPDATE_SLEEP 60

#define TRUSTEDGE_UPDATE_ITSELF_ARTIFACT \
    "{\n" \
    "    \"artifactId\":\"%s\",\n" \
    "    \"policyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"mode\":\"%s\",\n" \
    "    \"status\":\"%s\",\n" \
    "    \"timestamp\":\"%s\"\n" \
    "}\n"

/* Forward declarations */
extern sbyte** TRUSTEDGE_actionHandlerGenerateArgsWindows(TrustEdgeArtifactAction *pAction);
extern void TRUSTEDGE_actionHandlerDeleteArgsWindows(TrustEdgeArtifactAction *pAction);

/*------------------------------------------------------------------*/

static char* DIGI_STRTOLWR(char* s) {
    sbyte4 len = strlen(s);
    sbyte4 i = 0;
    for (i = 0; i < len; ++i)
        if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] += 'a' - 'A';
    return s;
}

/*------------------------------------------------------------------*/

/**
 * Escape a string for use in a PowerShell single-quoted string.
 * Single quotes must be doubled ('') to represent a literal single quote.
 * Returns OK on success with *ppOut containing the escaped string (caller must free).
 * Returns error if allocation fails.
 */
static MSTATUS TRUSTEDGE_escapePowerShellSingleQuote(const sbyte *pInput, sbyte **ppOut)
{
    const sbyte *p;
    sbyte *pOut;
    ubyte4 quoteCount = 0;
    ubyte4 inputLen;
    ubyte4 outputLen;
    MSTATUS status;

    if (NULL == pInput || NULL == ppOut)
        return ERR_NULL_POINTER;

    *ppOut = NULL;

    /* Count single quotes to determine output size */
    inputLen = DIGI_STRLEN(pInput);
    for (p = pInput; *p != '\0'; p++)
    {
        if (*p == '\'')
            quoteCount++;
    }

    /* Output size: original length + extra char for each quote + null terminator */
    outputLen = inputLen + quoteCount + 1;

    status = DIGI_MALLOC((void **)ppOut, outputLen);
    if (OK != status)
        return status;

    pOut = *ppOut;
    for (p = pInput; *p != '\0'; p++)
    {
        if (*p == '\'')
        {
            *pOut++ = '\'';
            *pOut++ = '\'';
        }
        else
        {
            *pOut++ = *p;
        }
    }
    *pOut = '\0';

    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentCreateStatusFile(TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    sbyte *pArtifactDir = NULL;
    sbyte *pFilePath = NULL;
    sbyte *pTimestamp = NULL;
    sbyte *pStr = NULL;
    FileDescriptorInfo fdInfo = { 0 };
    sbyte4 len;

    MSG_LOG_print(MSG_LOG_INFO, "Conf dir: %s\n", pCtx->pConfig->pConfDir);
    MSG_LOG_print(MSG_LOG_INFO, "Artifact ID : %s\n", pCtx->curPolicy.data.ups.pArtifact->pId);
    MSG_LOG_print(MSG_LOG_INFO, "Policy ID : %s\n", pCtx->curPolicy.pPolicy->pId);
    MSG_LOG_print(MSG_LOG_INFO, "Deployment ID : %s\n", pCtx->curPolicy.pPolicy->pDeploymentId);

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, ARTIFACTS_DIR , &pArtifactDir);
    if (OK != status)
    {
        goto exit;
    }
    MSG_LOG_print(MSG_LOG_INFO, "Artifact dir: %s\n", pArtifactDir);
    if (FALSE == FMGMT_pathExists(pArtifactDir, &fdInfo))
    {
        status = FMGMT_mkdir(pArtifactDir, 0744);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (FTDirectory != fdInfo.type)
    {
        /* if not a directory delete it */
        status = FMGMT_remove(pArtifactDir, FALSE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));

            goto exit;
        }

        status = FMGMT_mkdir(pArtifactDir, 0744);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = COMMON_UTILS_addPathComponent(
        pArtifactDir, pCtx->curPolicy.data.ups.pArtifact->pId, &pFilePath);
    if (OK != status)
    {
        goto exit;
    }
    MSG_LOG_print(MSG_LOG_VERBOSE, "Artifact status file : %s\n", pFilePath);

    status = TRUSTEDGE_utilsGetTime(&pTimestamp, 0);
    if(OK != status)
    {
        goto exit;
    }
    MSG_LOG_print(MSG_LOG_VERBOSE, "timestamp: %s\n", pTimestamp);

    len = snprintf(NULL, 0, TRUSTEDGE_UPDATE_ITSELF_ARTIFACT,
        pCtx->curPolicy.data.ups.pArtifact->pId,
        pCtx->curPolicy.pPolicy->pId,
        pCtx->curPolicy.pPolicy->pDeploymentId,
        "install",
        "Pending",
        pTimestamp);
    if (len <= 0)
    {
        status = ERR_TRUSTEDGE_AGENT;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MALLOC((void **) &pStr, len + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    len = snprintf(pStr, len + 1, TRUSTEDGE_UPDATE_ITSELF_ARTIFACT,
        pCtx->curPolicy.data.ups.pArtifact->pId,
        pCtx->curPolicy.pPolicy->pId,
        pCtx->curPolicy.pPolicy->pDeploymentId,
        "install",
        "Pending",
        pTimestamp);
    if (len <= 0)
    {
        status = ERR_TRUSTEDGE_AGENT;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGICERT_writeFile(pFilePath, pStr, len);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    DIGI_FREE((void **) &pArtifactDir);
    DIGI_FREE((void **) &pFilePath);
    DIGI_FREE((void **) &pTimestamp);
    DIGI_FREE((void **) &pStr);
    return status;
}

/*------------------------------------------------------------------*/

/**
 * Check if a Windows artifact is a TrustEdge self-update.
 * Similar to Linux version, but uses Windows Installer API to query MSI properties.
 */
static MSTATUS TRUSTEDGE_actionHandlerIsTrustedgeUpdateArtifact(
    TrustEdgeArtifactAction *pAction,
    sbyte *pDir,
    TrustEdgeAgentCtx *pCtx,
    intBoolean *te_update)
{
    MSTATUS status = OK;
    sbyte **ppS;
    sbyte *pStr = NULL;
    sbyte *pProductName = NULL;
    sbyte *ptr = NULL;
    MSIHANDLE hDatabase = 0;
    MSIHANDLE hView = 0;
    MSIHANDLE hRecord = 0;
    UINT msiResult;
    DWORD productNameSize = 256;
    sbyte4 i = 0;
    sbyte4 j = 0;
    sbyte **ppActionArgs = NULL;
    sbyte4 arraySize;

    *te_update = FALSE;

    /* Check for INSTALL action with SCRIPT handler and CMD/POWERSHELL/BATCH subtype */
    if (pAction->type == TE_ACTION_INSTALL
        && (pAction->handler.type == TE_ACTION_HANDLER_SCRIPT
            || pAction->handler.type == TE_ACTION_HANDLER_EXE))
    {
        MSG_LOG_print(MSG_LOG_VERBOSE, "Action Type: %s Handler Type: %s Subtype: %s\n",
            TRUSTEDGE_actionTypeToString(pAction->type),
            TRUSTEDGE_actionHandlerTypeToString(pAction->handler.type),
            TRUSTEDGE_actionHandlerSubTypeToString(pAction->handler.subtype));
        MSG_LOG_print(MSG_LOG_VERBOSE, "Action Path: %s \n", pAction->pActionPath);

        ppS = pAction->ppActionArgs;
        while (NULL != ppS[i])
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "      Arg[%d]: %s\n", i, ppS[i]);
            if (0 == DIGI_STRCMP(ppS[i], "--msi"))
            {
                MSG_LOG_print(MSG_LOG_VERBOSE, "%s\n", "Got --msi option");
                if (NULL == ppS[i+1])
                {
                    return ERR_TRUSTEDGE_AGENT;
                }

                status = DIGI_MALLOC((void **) &pStr, MAX_PATH_LENGTH + 1);
                if (OK != status)
                {
                    return ERR_TRUSTEDGE_AGENT;
                }
                MSG_LOG_print(MSG_LOG_VERBOSE, "pDir: %s\n", pDir);
                MSG_LOG_print(MSG_LOG_VERBOSE, "ppS[%d]: %s\n", i+1, ppS[i+1]);

                {
                    sbyte4 pathLen = snprintf(pStr, MAX_PATH_LENGTH + 1, "%s\\%s", pDir, ppS[i+1]);
                    if (pathLen < 0 || pathLen >= MAX_PATH_LENGTH + 1)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "%s\n", "MSI path truncated or snprintf failed");
                        status = ERR_TRUSTEDGE_AGENT;
                        goto exit;
                    }
                }
                MSG_LOG_print(MSG_LOG_VERBOSE, "MSI file: %s\n", pStr);

                if (FALSE == FMGMT_pathExists(pStr, NULL))
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "MSI file %s does not exist.\n", pStr);
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }
                MSG_LOG_print(MSG_LOG_VERBOSE, "MSI file %s exists.\n", pStr);

                /* Open the MSI database to read ProductName property */
                msiResult = MsiOpenDatabaseA(pStr, MSIDBOPEN_READONLY, &hDatabase);
                if (ERROR_SUCCESS != msiResult)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "Failed to open MSI database: %s (error: %u)\n",
                        pStr, msiResult);
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }

                /* Query the Property table for ProductName */
                msiResult = MsiDatabaseOpenViewA(hDatabase,
                    "SELECT `Value` FROM `Property` WHERE `Property` = 'ProductName'",
                    &hView);
                if (ERROR_SUCCESS != msiResult)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "Failed to open MSI view (error: %u)\n", msiResult);
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }

                msiResult = MsiViewExecute(hView, 0);
                if (ERROR_SUCCESS != msiResult)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "Failed to execute MSI view (error: %u)\n", msiResult);
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }

                msiResult = MsiViewFetch(hView, &hRecord);
                if (ERROR_SUCCESS != msiResult)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "Failed to fetch MSI record (error: %u)\n", msiResult);
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }

                /* Get the ProductName value */
                status = DIGI_MALLOC((void **) &pProductName, productNameSize + 1);
                if (OK != status)
                {
                    goto exit;
                }

                msiResult = MsiRecordGetStringA(hRecord, 1, pProductName, &productNameSize);
                if (ERROR_MORE_DATA == msiResult)
                {
                    /* Buffer too small; productNameSize now contains required size (excluding null) */
                    DIGI_FREE((void **) &pProductName);
                    status = DIGI_MALLOC((void **) &pProductName, productNameSize + 1);
                    if (OK != status)
                    {
                        goto exit;
                    }
                    msiResult = MsiRecordGetStringA(hRecord, 1, pProductName, &productNameSize);
                }
                if (ERROR_SUCCESS != msiResult)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "Failed to get ProductName (error: %u)\n", msiResult);
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }

                MSG_LOG_print(MSG_LOG_VERBOSE, "MSI ProductName: %s\n", pProductName);

                /* Convert to lowercase and check for "trustedge" */
                DIGI_STRTOLWR(pProductName);
                ptr = strstr(pProductName, "trustedge");
                if (ptr)
                {
                    MSG_LOG_print(MSG_LOG_VERBOSE, "Found TrustEdge in ProductName\n");
                    *te_update = TRUE;
                }
            }
            i++;
        }

        /* Add --aId and --service arguments if this is a TrustEdge self-update */
        if (*te_update == TRUE)
        {
            arraySize = i + 5;
            status = DIGI_MALLOC((void **) &ppActionArgs, sizeof(*ppActionArgs) * arraySize);
            if (OK != status)
                goto exit;
            for (j = 0; j < i; j++)
            {
                ppActionArgs[j] = ppS[j];
                MSG_LOG_print(MSG_LOG_VERBOSE, "ppActionArgs[%d]: %s\n", j, ppActionArgs[j]);
            }
            ppActionArgs[j++] = TRUSTEDGE_utilsCloneString("--aId");
            ppActionArgs[j++] = TRUSTEDGE_utilsCloneString(pCtx->curPolicy.data.ups.pArtifact->pId);
            ppActionArgs[j++] = TRUSTEDGE_utilsCloneString("--service");
            if (TRUE == pCtx->service)
                ppActionArgs[j++] = TRUSTEDGE_utilsCloneString("TRUE");
            else
                ppActionArgs[j++] = TRUSTEDGE_utilsCloneString("FALSE");
            ppActionArgs[j++] = NULL;

            DIGI_FREE((void **) &pAction->ppActionArgs);
            pAction->ppActionArgs = ppActionArgs;

            MSG_LOG_print(MSG_LOG_VERBOSE, "%s:\n", "Printing modified array");
            j = 0;
            while (pAction->ppActionArgs[j])
            {
                MSG_LOG_print(MSG_LOG_VERBOSE, "pAction->ppActionArgs[%d]: %s\n",
                    j, pAction->ppActionArgs[j]);
                j++;
            }
            ppActionArgs = NULL;
            MSG_LOG_print(MSG_LOG_VERBOSE, "%s:\n", "Array modified successfully");
        }
    }

exit:
    if (hRecord) MsiCloseHandle(hRecord);
    if (hView) MsiCloseHandle(hView);
    if (hDatabase) MsiCloseHandle(hDatabase);
    DIGI_FREE((void **) &pStr);
    DIGI_FREE((void **) &pProductName);
    return status;
}

/*------------------------------------------------------------------*/

/**
 * Check if a Windows command-line argument needs quoting.
 * Arguments need quoting if they contain spaces, tabs, quotes, or are empty.
 */
static intBoolean TRUSTEDGE_argNeedsQuoting(const sbyte *pArg)
{
    const sbyte *p;
    
    if (pArg == NULL || *pArg == '\0')
        return TRUE;  /* Empty args need quoting */
    
    for (p = pArg; *p != '\0'; p++)
    {
        if (*p == ' ' || *p == '\t' || *p == '"')
            return TRUE;
    }
    return FALSE;
}

/**
 * Calculate the size needed for a properly escaped Windows command-line argument.
 * Following Windows escaping rules:
 * - Backslashes before quotes must be doubled, plus one more to escape the quote
 * - Trailing backslashes before closing quote must be doubled
 */
static ubyte4 TRUSTEDGE_calcEscapedArgSize(const sbyte *pArg)
{
    const sbyte *p;
    ubyte4 size = 0;
    ubyte4 numBackslashes = 0;
    
    if (pArg == NULL)
        return 3;  /* "" + null */
    
    if (!TRUSTEDGE_argNeedsQuoting(pArg))
        return DIGI_STRLEN(pArg) + 1;  /* No quoting needed */
    
    size = 2;  /* Opening and closing quotes */
    
    for (p = pArg; *p != '\0'; p++)
    {
        if (*p == '\\')
        {
            numBackslashes++;
        }
        else if (*p == '"')
        {
            /* Double backslashes before quote, plus one for escaping the quote */
            size += numBackslashes * 2 + 2;  /* 2N backslashes + \" */
            numBackslashes = 0;
        }
        else
        {
            size += numBackslashes + 1;  /* N backslashes + character */
            numBackslashes = 0;
        }
    }
    
    /* Trailing backslashes must be doubled before closing quote */
    size += numBackslashes * 2;
    
    return size + 1;  /* +1 for null terminator */
}

/**
 * Write a properly escaped Windows command-line argument to buffer.
 * Returns the number of characters written (excluding null terminator).
 */
static sbyte4 TRUSTEDGE_writeEscapedArg(sbyte *pDst, ubyte4 dstSize, const sbyte *pArg)
{
    const sbyte *pSrc;
    sbyte *pOut = pDst;
    sbyte *pEnd = pDst + dstSize - 1;  /* Leave room for null */
    ubyte4 numBackslashes = 0;
    ubyte4 i;
    
    if (pDst == NULL || dstSize == 0)
        return -1;
    
    if (pArg == NULL)
    {
        if (dstSize < 3)
            return -1;
        pDst[0] = '"';
        pDst[1] = '"';
        pDst[2] = '\0';
        return 2;
    }
    
    /* If no quoting needed, just copy */
    if (!TRUSTEDGE_argNeedsQuoting(pArg))
    {
        ubyte4 len = DIGI_STRLEN(pArg);
        if (len >= dstSize)
            return -1;
        memcpy(pDst, pArg, len);
        pDst[len] = '\0';
        return (sbyte4)len;
    }
    
    /* Opening quote */
    if (pOut >= pEnd)
        return -1;
    *pOut++ = '"';
    
    for (pSrc = pArg; *pSrc != '\0'; pSrc++)
    {
        if (*pSrc == '\\')
        {
            numBackslashes++;
        }
        else if (*pSrc == '"')
        {
            /* Double all backslashes before quote */
            for (i = 0; i < numBackslashes * 2; i++)
            {
                if (pOut >= pEnd)
                    return -1;
                *pOut++ = '\\';
            }
            /* Escape the quote */
            if (pOut >= pEnd)
                return -1;
            *pOut++ = '\\';
            if (pOut >= pEnd)
                return -1;
            *pOut++ = '"';
            numBackslashes = 0;
        }
        else
        {
            /* Output accumulated backslashes (not doubled) */
            for (i = 0; i < numBackslashes; i++)
            {
                if (pOut >= pEnd)
                    return -1;
                *pOut++ = '\\';
            }
            if (pOut >= pEnd)
                return -1;
            *pOut++ = *pSrc;
            numBackslashes = 0;
        }
    }
    
    /* Double trailing backslashes before closing quote */
    for (i = 0; i < numBackslashes * 2; i++)
    {
        if (pOut >= pEnd)
            return -1;
        *pOut++ = '\\';
    }
    
    /* Closing quote */
    if (pOut >= pEnd)
        return -1;
    *pOut++ = '"';
    
    *pOut = '\0';
    return (sbyte4)(pOut - pDst);
}

/*------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_launchActionHandlerWindows(
    TrustEdgeArtifactAction *pAction,
    sbyte *pDir,
    TrustEdgeAgentCtx *pCtx
)
{
    MSTATUS status = OK;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    sbyte *pCommandLine = NULL;
    ubyte4 cmdLineSize = 0;
    ubyte4 cmdLineOffset = 0;
    sbyte *pFullPath = NULL;
    sbyte **ppArgs = NULL;
    sbyte4 i;
    DWORD exitCode;
    sbyte4 written;
    intBoolean isTEUpdateArtifact = FALSE;

    if (NULL == pAction || NULL == pCtx || NULL == pDir)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Windows requires an executable path for all actions.
     * Unlike Linux, Windows doesn't have built-in package managers (dpkg/rpm)
     * for rollback actions - a custom rollback script must be provided. */
    if (NULL == pAction->pActionPath)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s: Action type '%d' requires an executable path (pActionPath is NULL). "
            "Windows does not support package manager rollback without a custom script.\n",
            __func__, pAction->type);
        status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
        goto exit;
    }

    /* Build full path to executable by prepending artifact directory */
    status = COMMON_UTILS_addPathComponent(pDir, pAction->pActionPath, &pFullPath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s: Failed to build full path for %s\n", 
            __func__, pAction->pActionPath);
        goto exit;
    }
    MSG_LOG_print(MSG_LOG_DEBUG, "%s: Full executable path: %s\n", __func__, pFullPath);
    
    /* Temporarily replace action path with full path for args generation */
    {
        sbyte *pOrigPath = pAction->pActionPath;
        pAction->pActionPath = pFullPath;
        /* Free any previously generated args before replacing them to avoid leaking
         * the argv array populated earlier (for example by the manifest parser). */
        TRUSTEDGE_actionHandlerDeleteArgsWindows(pAction);
        ppArgs = TRUSTEDGE_actionHandlerGenerateArgsWindows(pAction);
        pAction->pActionPath = pOrigPath;  /* Restore original */
    }

    if (NULL == ppArgs || NULL == ppArgs[0])
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s: Failed to generate args\n", __func__);
        status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
        goto exit;
    }

    /* Check if this is a TrustEdge self-update artifact */
    status = TRUSTEDGE_actionHandlerIsTrustedgeUpdateArtifact(pAction, pDir, pCtx, &isTEUpdateArtifact);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s: Failed to check if artifact is TrustEdge update\n", __func__);
        status = ERR_TRUSTEDGE_AGENT;
        goto exit;
    }

    /* Refresh ppArgs after potential modification by isTrustedgeUpdateArtifact */
    ppArgs = pAction->ppActionArgs;

    /* Calculate required buffer size for command line with proper escaping */
    for (i = 0; ppArgs[i] != NULL; i++)
    {
        /* Add space for properly escaped argument and space separator */
        cmdLineSize += TRUSTEDGE_calcEscapedArgSize(ppArgs[i]) + 1;  /* +1 for space */
    }
    cmdLineSize += 1;  /* null terminator */

    status = DIGI_MALLOC((void **)&pCommandLine, cmdLineSize);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s: Failed to allocate command line buffer\n", __func__);
        goto exit;
    }

    /* Build command line with proper Windows escaping */
    pCommandLine[0] = '\0';
    cmdLineOffset = 0;
    for (i = 0; ppArgs[i] != NULL; i++)
    {
        if (i > 0)
        {
            written = snprintf(pCommandLine + cmdLineOffset, cmdLineSize - cmdLineOffset, " ");
            if (written < 0 || (ubyte4)written >= cmdLineSize - cmdLineOffset)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "%s: Command line buffer overflow\n", __func__);
                status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
                goto exit;
            }
            cmdLineOffset += written;
        }
        /* Properly escape argument following Windows command-line rules */
        written = TRUSTEDGE_writeEscapedArg(pCommandLine + cmdLineOffset, 
            cmdLineSize - cmdLineOffset, ppArgs[i]);
        if (written < 0 || (ubyte4)written >= cmdLineSize - cmdLineOffset)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: Command line buffer overflow\n", __func__);
            status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
            goto exit;
        }
        cmdLineOffset += written;
    }

    /* Log execution at DEBUG level. Note: full command line may contain sensitive data. */
    MSG_LOG_print(MSG_LOG_DEBUG, "%s: Executing: %s (argc=%d)\n", __func__, pFullPath, i);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    /* For TrustEdge self-update, we need the spawned process to sleep before running,
     * similar to how Linux forks and the child sleeps before exec.
     * Use PowerShell's Start-Sleep which works reliably in headless/detached processes.
     * PowerShell is guaranteed on Windows 7+ and all modern Windows versions. */
    if (isTEUpdateArtifact)
    {
        sbyte *pWrappedCmd = NULL;
        sbyte *pEscapedDir = NULL;
        sbyte *pEscapedCmdLine = NULL;
        sbyte4 wrappedLen;
        const sbyte *pLogFile = "C:\\ProgramData\\DigiCert\\TrustEdge\\update_script.log";

        /* Escape single quotes in pDir and pCommandLine for PowerShell single-quoted strings.
         * In PowerShell, single quotes inside single-quoted strings must be doubled. */
        status = TRUSTEDGE_escapePowerShellSingleQuote(pDir, &pEscapedDir);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: Failed to escape directory path\n", __func__);
            goto exit;
        }

        status = TRUSTEDGE_escapePowerShellSingleQuote(pCommandLine, &pEscapedCmdLine);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: Failed to escape command line\n", __func__);
            DIGI_FREE((void **)&pEscapedDir);
            goto exit;
        }

        /* Compute exact size needed for PowerShell command using snprintf with NULL.
         * Use Out-File instead of *>> because stream redirection doesn't work
         * reliably in detached processes without a console. */
        wrappedLen = snprintf(NULL, 0,
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \""
            "Start-Sleep -Seconds %d; "
            "Set-Location -LiteralPath '%s'; "
            "$output = & cmd.exe /c '%s' 2>&1; "
            "$output | Out-File -FilePath '%s' -Append -Encoding UTF8\"",
            TRUSTEDGE_UPDATE_SLEEP, pEscapedDir, pEscapedCmdLine, pLogFile);
        if (wrappedLen <= 0)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: Failed to compute wrapped command size\n", __func__);
            DIGI_FREE((void **)&pEscapedDir);
            DIGI_FREE((void **)&pEscapedCmdLine);
            status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
            goto exit;
        }

        status = DIGI_MALLOC((void **)&pWrappedCmd, wrappedLen + 1);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: Failed to allocate wrapped command buffer\n", __func__);
            DIGI_FREE((void **)&pEscapedDir);
            DIGI_FREE((void **)&pEscapedCmdLine);
            goto exit;
        }

        /* Now write the actual command */
        wrappedLen = snprintf(pWrappedCmd, wrappedLen + 1,
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \""
            "Start-Sleep -Seconds %d; "
            "Set-Location -LiteralPath '%s'; "
            "$output = & cmd.exe /c '%s' 2>&1; "
            "$output | Out-File -FilePath '%s' -Append -Encoding UTF8\"",
            TRUSTEDGE_UPDATE_SLEEP, pEscapedDir, pEscapedCmdLine, pLogFile);

        DIGI_FREE((void **)&pEscapedDir);
        DIGI_FREE((void **)&pEscapedCmdLine);

        if (wrappedLen <= 0)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: Failed to build wrapped command\n", __func__);
            DIGI_FREE((void **)&pWrappedCmd);
            status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
            goto exit;
        }

        /* Log short message - don't log full command as it may overflow MSG_LOG buffer */
        MSG_LOG_print(MSG_LOG_VERBOSE, "%s: TrustEdge self-update, spawning PowerShell with %d sec delay, log: %s\n",
            __func__, TRUSTEDGE_UPDATE_SLEEP, pLogFile);

        /* Launch PowerShell with the command - it will wait then run the update.
         * Use CREATE_NO_WINDOW instead of DETACHED_PROCESS because DETACHED_PROCESS
         * prevents PowerShell from executing commands properly (no console I/O). */
        if (!CreateProcessA(NULL, pWrappedCmd, NULL, NULL, FALSE,
            CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW, NULL, pDir, &si, &pi))
        {
            DWORD lastError = GetLastError();
            MSG_LOG_print(MSG_LOG_ERROR, "%s: CreateProcessA failed with error %lu\n", __func__, lastError);
            DIGI_FREE((void **)&pWrappedCmd);
            status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
            goto exit;
        }

        DIGI_FREE((void **)&pWrappedCmd);

        /* Mark as async and create status file - parent returns immediately */
        pCtx->curPolicy.data.ups.pArtifact->isAsync = TRUE;
        MSG_LOG_print(MSG_LOG_VERBOSE, "%s: TrustEdge agent self-update started asynchronously\n", __func__);
        status = TRUSTEDGE_agentCreateStatusFile(pCtx);

        /* Close handles and return - don't wait for the update process */
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        goto exit;
    }

    /* Pass full path as lpApplicationName to avoid path resolution issues.
     * Use pDir as the working directory so scripts can find payload files
     * using relative paths (e.g., payload\package\*.msi). */
    if (!CreateProcessA(pFullPath, pCommandLine, NULL, NULL, FALSE, 0, NULL, pDir, &si, &pi))
    {
        DWORD lastError = GetLastError();
        MSG_LOG_print(MSG_LOG_ERROR, "%s: CreateProcessA failed with error %lu\n", __func__, lastError);
        status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_DEBUG, "%s: Process started, waiting up to %d seconds\n",
        __func__, pCtx->actionHandlerTimeout);

    /* Wait for process with timeout (convert seconds to ms) */
    {
        DWORD timeoutMs;
        DWORD waitResult;
        sbyte4 effectiveTimeout = pCtx->actionHandlerTimeout;

        /* Validate timeout: treat negative as 0, cap to prevent overflow (max ~24.8 days) */
        if (pCtx->actionHandlerTimeout <= 0)
            timeoutMs = 0;
        else if (pCtx->actionHandlerTimeout > 2147483)  /* Max before overflow in ms */
        {
            effectiveTimeout = 2147483;
            timeoutMs = 2147483000;  /* 2147483 * 1000 */
            MSG_LOG_print(MSG_LOG_WARNING, "%s: Timeout %d seconds exceeds maximum, truncating to %d seconds\n",
                __func__, pCtx->actionHandlerTimeout, effectiveTimeout);
        }
        else
            timeoutMs = (DWORD)(pCtx->actionHandlerTimeout * 1000);

        waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
        if (waitResult == WAIT_TIMEOUT)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: Process timed out after %d seconds\n",
                __func__, effectiveTimeout);
            if (!TerminateProcess(pi.hProcess, 1))
            {
                DWORD lastError = GetLastError();
                MSG_LOG_print(MSG_LOG_ERROR, "%s: TerminateProcess failed with error %lu\n",
                    __func__, lastError);
            }
            status = ERR_TRUSTEDGE_AGENT_ACTION_TIMEOUT;
        }
        else if (waitResult == WAIT_FAILED)
        {
            DWORD lastError = GetLastError();
            MSG_LOG_print(MSG_LOG_ERROR, "%s: WaitForSingleObject failed with error %lu\n",
                __func__, lastError);
            status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
        }
        else if (waitResult == WAIT_OBJECT_0)
        {
            if (!GetExitCodeProcess(pi.hProcess, &exitCode))
            {
                DWORD lastError = GetLastError();
                MSG_LOG_print(MSG_LOG_ERROR, "%s: GetExitCodeProcess failed with error %lu\n",
                    __func__, lastError);
                status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
            }
            else
            {
                MSG_LOG_print(MSG_LOG_INFO, "%s: Process exited with code %lu\n", __func__, exitCode);
                if (exitCode != 0)
                    status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
            }
        }
        else
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: WaitForSingleObject returned unexpected result %lu\n",
                __func__, waitResult);
            status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
        }
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

exit:
    if (ppArgs != NULL)
        TRUSTEDGE_actionHandlerDeleteArgsWindows(pAction);

    DIGI_FREE((void **)&pCommandLine);
    DIGI_FREE((void **)&pFullPath);

    return status;
}

/*------------------------------------------------------------------*/

extern sbyte** TRUSTEDGE_actionHandlerGenerateArgsWindows(TrustEdgeArtifactAction *pAction)
{
    sbyte **ppArgs = NULL;
    sbyte4 numArgs = 0;
    sbyte4 i;
    sbyte *pArgStr;

    if (NULL == pAction)
        return NULL;

    /* Count args: 1 for path + args from pActionArgument */
    numArgs = 1;
    pArgStr = pAction->pActionArgument;
    if (pArgStr != NULL)
    {
        sbyte *p = pArgStr;
        while (*p)
        {
            while (*p && *p == ' ') p++;
            if (*p) numArgs++;
            while (*p && *p != ' ') p++;
        }
    }

    /* Allocate args array */
    if (OK != DIGI_CALLOC((void **)&ppArgs, numArgs + 1, sizeof(sbyte*)))
        return NULL;

    /* Set command path */
    if (pAction->pActionPath != NULL)
    {
        size_t actionPathLen = strlen(pAction->pActionPath);
        if (OK != DIGI_MALLOC((void **)&ppArgs[0], actionPathLen + 1))
        {
            DIGI_FREE((void **)&ppArgs);
            return NULL;
        }
        memcpy(ppArgs[0], pAction->pActionPath, actionPathLen + 1);
    }

    /* Parse additional args if any */
    if (pArgStr != NULL && numArgs > 1)
    {
        sbyte *p = pArgStr;
        sbyte *start;
        i = 1;
        while (*p && i < numArgs)
        {
            while (*p && *p == ' ') p++;
            start = p;
            while (*p && *p != ' ') p++;
            if (p > start)
            {
                sbyte4 len = (sbyte4)(p - start);
                if (OK != DIGI_MALLOC((void **)&ppArgs[i], len + 1))
                    break;
                memcpy(ppArgs[i], start, len);
                ppArgs[i][len] = '\0';
                i++;
            }
        }
    }

    ppArgs[numArgs] = NULL;
    pAction->ppActionArgs = ppArgs;
    return ppArgs;
}

/*------------------------------------------------------------------*/

extern void TRUSTEDGE_actionHandlerDeleteArgsWindows(TrustEdgeArtifactAction *pAction)
{
    sbyte **ppS;
    sbyte4 i;

    if (NULL == pAction || NULL == pAction->ppActionArgs)
        return;

    ppS = pAction->ppActionArgs;
    i = 0;
    while (NULL != ppS[i])
    {
        DIGI_FREE((void **) &ppS[i++]);
    }

    DIGI_FREE((void **) &(pAction->ppActionArgs));
    pAction->ppActionArgs = NULL;
}

/*------------------------------------------------------------------*/
/* Stub for TRUSTEDGE_ENROLL_resourceUpdateHandler on Windows */
/* This function is normally in trustedge_certificate_main.c but that
 * file has dependencies not suitable for library builds.
 * Only compile this stub when trustedge_certificate_main.c is NOT included. */
/*------------------------------------------------------------------*/
#if defined(__DISABLE_TRUSTEDGE_SCEP__) && defined(__DISABLE_TRUSTEDGE_EST__)
extern MSTATUS TRUSTEDGE_ENROLL_resourceUpdateHandler(void *pResource)
{
    MOC_UNUSED(pResource);
    /* Return ERR_CERT_NOT_FOUND to indicate no one has subscribed to this resource
     * The caller handles this gracefully and continues */
    return ERR_CERT_NOT_FOUND;
}
#endif /* __DISABLE_TRUSTEDGE_SCEP__ && __DISABLE_TRUSTEDGE_EST__ */

#endif /* __RTOS_WIN32__ */
