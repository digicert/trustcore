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
#include "../../common/msg_logger.h"
#include "../../common/common_utils.h"
#include "../../trustedge/utils/trustedge_utils.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../trustedge/agent/trustedge_agent_updatepolicy.h"

/* Forward declarations */
extern sbyte** TRUSTEDGE_actionHandlerGenerateArgsWindows(TrustEdgeArtifactAction *pAction);
extern void TRUSTEDGE_actionHandlerDeleteArgsWindows(TrustEdgeArtifactAction *pAction);

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

    /* Pass full path as lpApplicationName to avoid path resolution issues */
    if (!CreateProcessA(pFullPath, pCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
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

        /* Validate timeout: treat negative as 0, cap to prevent overflow (max ~49 days) */
        if (pCtx->actionHandlerTimeout <= 0)
            timeoutMs = 0;
        else if (pCtx->actionHandlerTimeout > 2147483)  /* Max before overflow in ms */
            timeoutMs = INFINITE;
        else
            timeoutMs = (DWORD)(pCtx->actionHandlerTimeout * 1000);

        waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
        if (waitResult == WAIT_TIMEOUT)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: Process timed out after %d seconds\n",
                __func__, pCtx->actionHandlerTimeout);
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
