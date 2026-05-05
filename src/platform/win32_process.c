/*
 * win32_process.c
 *
 * Win32 Process Abstraction Layer
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

#include "../common/moptions.h"

#if defined(__RTOS_WIN32__)
#if defined(__ENABLE_DIGICERT_RTOS_PROCESS__)

#include <windows.h>
#include <stdio.h>

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
WIN32_processExecute(sbyte* pCmd, sbyte** ppOutput)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    MSTATUS status = OK;

    MOC_UNUSED(ppOutput);

    if (NULL == pCmd)
        return ERR_NULL_POINTER;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, pCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        status = ERR_GENERAL;
        goto exit;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

exit:
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
WIN32_processExecuteWithArg(sbyte* pCmd, sbyte* pArg, sbyte** ppOutput)
{
    sbyte commandLine[2048];
    MSTATUS status = OK;

    MOC_UNUSED(ppOutput);

    if (NULL == pCmd)
        return ERR_NULL_POINTER;

    /* Build command line with argument */
    if (pArg != NULL)
    {
        snprintf(commandLine, sizeof(commandLine), "%s %s", pCmd, pArg);
        status = WIN32_processExecute(commandLine, NULL);
    }
    else
    {
        status = WIN32_processExecute(pCmd, NULL);
    }

    return status;
}

/*------------------------------------------------------------------*/

#endif /* __ENABLE_DIGICERT_RTOS_PROCESS__ */
#endif /* __RTOS_WIN32__ */
