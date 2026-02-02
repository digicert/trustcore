/*
 * wince_rtos.c
 *
 * WinCE RTOS Abstraction Layer
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#if defined( __WINCE_RTOS__) || defined(__RTOS_WINCE__)

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#include <time.h>

extern MSTATUS
WINCE_rtosInit(void)
{
    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    HANDLE mutexHandle;
    MSTATUS status = OK;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (mutexHandle = CreateMutex(NULL, FALSE, NULL)))
        status = ERR_RTOS_MUTEX_CREATE;
    else
        *pMutex = (RTOS_MUTEX)mutexHandle;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_mutexWait(RTOS_MUTEX mutex)
{
    HANDLE  mutexHandle = (HANDLE)mutex;
    MSTATUS status = OK;

    if (WAIT_OBJECT_0 != WaitForSingleObject(mutexHandle, 5000L))
        status = ERR_RTOS_MUTEX_WAIT;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_mutexRelease(RTOS_MUTEX mutex)
{
    HANDLE  mutexHandle = (HANDLE)mutex;
    MSTATUS status = OK;

    if (!ReleaseMutex(mutexHandle))
        status = ERR_RTOS_MUTEX_RELEASE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_mutexFree(RTOS_MUTEX* pMutex)
{
    HANDLE mutexHandle;
    MSTATUS status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    mutexHandle = (HANDLE)(*pMutex);

    if (0 != CloseHandle(mutexHandle))
    {
        *pMutex = NULL;
        status  = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte4
WINCE_getUpTimeInMS(void)
{
    return GetTickCount();
}


/*------------------------------------------------------------------*/

extern ubyte4
WINCE_deltaMS(const moctime_t* origin, moctime_t* current)
{
    FILETIME fileTime;
    SYSTEMTIME sysTime;
    ULARGE_INTEGER int64Time;
    ubyte4 retVal = 0;

    GetSystemTime(&sysTime);
    SystemTimeToFileTime(&sysTime, &fileTime);
    /* file time is the number of 100 ns (0.1 us) since an epoch */
    /* MSDN says don't cast to ULARGE_INTEGER for windows 64 compat */
    int64Time.LowPart = fileTime.dwLowDateTime;
    int64Time.HighPart = fileTime.dwHighDateTime;
    /* convert to ms */
    int64Time.QuadPart /= ((ULONGLONG)10000);

    if(origin)
    {
        ULARGE_INTEGER old;
        old.HighPart = origin->u.time[0];
        old.LowPart = origin->u.time[1];

        old.QuadPart = int64Time.QuadPart - old.QuadPart;

        if (old.HighPart > 0)
        {
            /* saturate */
            retVal = 0xFFFFFFFF;
        }
        else
        {
            retVal = old.LowPart;
        }
    }

    if (current)
    {
        current->u.time[0] = int64Time.HighPart;
        current->u.time[1] = int64Time.LowPart;
    }
    return retVal;
}


/*------------------------------------------------------------------*/

extern ubyte4
WINCE_deltaConstMS(const moctime_t* origin, const moctime_t* current)
{
    ULARGE_INTEGER old, curr;

    old.HighPart = origin->u.time[0];
    old.LowPart = origin->u.time[1];
    curr.HighPart = current->u.time[0];
    curr.LowPart = current->u.time[1];

    curr.QuadPart -= old.QuadPart;

    return (curr.HighPart > 0) ? 0xFFFFFFFF : curr.LowPart;
}


/*------------------------------------------------------------------*/

extern moctime_t *
WINCE_timerAddMS(moctime_t* pTimer, ubyte4 addNumMS)
{
    ULARGE_INTEGER tmp;

    tmp.HighPart = pTimer->u.time[0];
    tmp.LowPart = pTimer->u.time[1];

    tmp.QuadPart += (ULONGLONG) addNumMS;

    pTimer->u.time[0] = tmp.HighPart;
    pTimer->u.time[1] = tmp.LowPart;

    return pTimer;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    DWORD   dwThreadId;
    HANDLE  hThread;
    MSTATUS status      = OK;
    MOC_UNUSED(threadType);

    /* threadType is ignored for this platform, use default values */

    hThread = (HANDLE) CreateThread(
        NULL,                        /* no security attributes */
        0,                           /* default stack size */
        (LPTHREAD_START_ROUTINE)
                    threadEntry,     /* thread function */
        context,                     /* argument to thread function */
        0,                           /* use default creation flags */
        &dwThreadId);                /* returns the thread identifier */

    if (hThread == NULL)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "WINCE_createThread: CreateThread() failed.");
        status = ERR_RTOS_THREAD_CREATE;
    }

    *pRetTid = hThread;

    return status;
}


/*------------------------------------------------------------------*/

extern void
WINCE_sleepMS(ubyte4 sleepTimeInMS)
{
    Sleep(sleepTimeInMS);
}


/*------------------------------------------------------------------*/

extern void
WINCE_destroyThread(RTOS_THREAD handle)
{
    CloseHandle((void *)handle);
}


/*------------------------------------------------------------------*/

extern sbyte4
WINCE_currentThreadId()
{
    return GetCurrentThreadId();
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_timeGMT(TimeDate* td)
{
    SYSTEMTIME sm;
    if (0 == td)
    {
        return ERR_NULL_POINTER;
    }

    GetSystemTime( &sm);

    td->m_year   = (ubyte)(sm.wYear - 1970);
    td->m_month  = (ubyte)sm.wMonth;
    td->m_day    = (ubyte)sm.wDay;
    td->m_hour   = (ubyte)sm.wHour;
    td->m_minute = (ubyte)sm.wMinute;
    td->m_second = (ubyte)sm.wSecond;

    return OK;
}


#endif /* __WINCE_RTOS__ */
