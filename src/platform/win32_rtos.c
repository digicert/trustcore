/*
 * win32_rtos.c
 *
 * Win32 RTOS Abstraction Layer
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

#if defined(__ENABLE_DIGICERT_WIN_STUDIO_BUILD__)
#include <winsock2.h>
#include <Ws2tcpip.h>
#endif
#include "../common/moptions.h"

#ifdef __RTOS_WIN32__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#ifdef CR
#undef CR
#endif

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <Iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#include <process.h>
#include <sys/timeb.h>
#include <io.h>
#include <sys/locking.h>
#include <fcntl.h>


#if defined(_DEBUG)
#include <crtdbg.h>
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_rtosInit(void)
{
    MSTATUS status = OK;

#if defined(__RTOS_WIN32__) && defined(_DEBUG)
    /* print memory leaks on exit */
    _CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    /* Send all reports to STDOUT */
   _CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_DEBUG );
   _CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_DEBUG );
   _CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_DEBUG );
#endif

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
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
WIN32_mutexWait(RTOS_MUTEX mutex)
{
    HANDLE  mutexHandle = (HANDLE)mutex;
    MSTATUS status = OK;

    if (WAIT_OBJECT_0 != WaitForSingleObject(mutexHandle, 5000L))
        status = ERR_RTOS_MUTEX_WAIT;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_mutexRelease(RTOS_MUTEX mutex)
{
    HANDLE  mutexHandle = (HANDLE)mutex;
    MSTATUS status = OK;

    if (!ReleaseMutex(mutexHandle))
        status = ERR_RTOS_MUTEX_RELEASE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_mutexFree(RTOS_MUTEX* pMutex)
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

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
/*------------------------------------------------------------------*/
extern MSTATUS
WIN32_globalMutexCreate(char *mutexName, RTOS_GLOBAL_MUTEX* ppMutex)
{
    MSTATUS status = OK;
    HANDLE hMutex;

    if (NULL == (hMutex = CreateMutexA(NULL, FALSE, mutexName)))
    {
        status = ERR_RTOS_MUTEX_CREATE;
        goto exit;
    }

    *ppMutex = (RTOS_GLOBAL_MUTEX)hMutex;

exit:
    return status;
}

/*------------------------------------------------------------------*/
extern MSTATUS
WIN32_globalMutexWait(RTOS_GLOBAL_MUTEX pMutex, ubyte4 timeoutInSecs)
{
    MSTATUS status = OK;
    HANDLE hMutex;

    if (NULL != pMutex)
    {
        hMutex = (HANDLE)pMutex;
        DWORD dwWaitResult = WaitForSingleObject(hMutex, INFINITE);
        if (WAIT_OBJECT_0 != dwWaitResult)
        {
            DB_PRINT("[MAJOR]: win32_rtos: GlobalMutex Wait failed with error %d", dwWaitResult);
            status = ERR_RTOS_MUTEX_WAIT;
            goto exit;
        }
    }
    else
    {
        status = ERR_RTOS_MUTEX_WAIT;
        goto exit;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/
extern MSTATUS
WIN32_globalMutexRelease(RTOS_GLOBAL_MUTEX pMutex)
{
    MSTATUS status = OK;
    HANDLE hMutex;

    if (NULL != pMutex)
    {
        hMutex = (HANDLE)pMutex;
        if (0 == ReleaseMutex(hMutex))
        {
            status = ERR_RTOS_MUTEX_RELEASE;
            goto exit;
        }
    }
    else
    {
        status = ERR_RTOS_MUTEX_RELEASE;
        goto exit;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/
extern MSTATUS
WIN32_globalMutexFree(char *mutexName, RTOS_GLOBAL_MUTEX* ppMutex)
{
    MSTATUS status = ERR_RTOS_MUTEX_FREE;
    HANDLE hMutex;

    if ((NULL == ppMutex) || (NULL == *ppMutex))
        goto exit;

    hMutex = (HANDLE)(*ppMutex);

    CloseHandle(hMutex);

    status = OK;

exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

extern ubyte4
WIN32_getUpTimeInMS(void)
{
    return GetTickCount();
}


/*------------------------------------------------------------------*/

extern ubyte4
WIN32_deltaMS(const moctime_t* origin, moctime_t* current)
{
    FILETIME fileTime;
    ULARGE_INTEGER int64Time;
    ubyte4 retVal = 0;

    GetSystemTimeAsFileTime(&fileTime);
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
WIN32_deltaConstMS(const moctime_t* origin, const moctime_t* current)
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
WIN32_timerAddMS(moctime_t* pTimer, ubyte4 addNumMS)
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
WIN32_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    DWORD   dwThreadId;
    HANDLE  hThread;
    MSTATUS status      = OK;
    MOC_UNUSED(threadType);

    /* threadType is ignored for this platform, use default values */

    hThread = (HANDLE) _beginthreadex(
        NULL,                        /* no security attributes */
        0,                           /* default stack size */
        (LPTHREAD_START_ROUTINE)
                    threadEntry,     /* thread function */
        context,                     /* argument to thread function */
        0,                           /* use default creation flags */
        &dwThreadId);                /* returns the thread identifier */

    if (hThread == NULL)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "WIN32_createThread: CreateThread() failed.");
        status = ERR_RTOS_THREAD_CREATE;
    }

    *pRetTid = hThread;

    return status;
}


/*------------------------------------------------------------------*/

extern void
WIN32_sleepMS(ubyte4 sleepTimeInMS)
{
    Sleep(sleepTimeInMS);
}


/*------------------------------------------------------------------*/

extern void
WIN32_destroyThread(RTOS_THREAD handle)
{
    CloseHandle((void *)handle);
}


/*------------------------------------------------------------------*/

extern sbyte4
WIN32_currentThreadId()
{
    return GetCurrentThreadId();
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
WIN32_timeGMT(TimeDate* td)
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

/*------------------------------------------------------------------*/
/**
* @brief Function to retrieve HW MAC address
* @note In param macAddr should point to memory of minimum size 6 to hold a MAC address value
*/
MOC_EXTERN MSTATUS
WIN32_getHwAddrByIfname(const sbyte *ifname, sbyte *adapter_name, ubyte *macAddr, ubyte4 len)
{
    MSTATUS status = ERR_GENERAL;
    PIP_ADAPTER_INFO pIpAdapterInfo = NULL;
    DWORD dwBufLen = sizeof(pIpAdapterInfo);    /*Temporary buffer size until the actual is computed*/
    unsigned long adapterInfoStatus = NO_ERROR;
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ubyte4 iterator;

    /*MAC address value needs 48 bit to fit*/
    if (NULL == macAddr || 6 > len)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /*Adaptor description should not be empty*/
    if ((NULL == ifname) || ((MAX_ADAPTER_DESCRIPTION_LENGTH + 4) < DIGI_STRLEN(ifname)))
    {
        DB_PRINT("win32_rtos: Adaptor Description is NULL");
        status = ERR_INVALID_ARG;
        goto exit;
    }
    DB_PRINT("win32_rtos: Adaptor Description is: %s\n", ifname);
    pIpAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (NULL == pIpAdapterInfo)
    {
        DB_PRINT("win32_rtos: Error allocating memory needed to call GetAdaptersinfo\n");
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /*Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable*/
    adapterInfoStatus = GetAdaptersInfo(pIpAdapterInfo, &dwBufLen);
    if (NO_ERROR != adapterInfoStatus && ERROR_BUFFER_OVERFLOW != adapterInfoStatus)
    {
        DB_PRINT("win32_rtos: Error calling GetAdaptersinfo. Received error = %lu\n", adapterInfoStatus);
        status = ERR_GENERAL;
        goto exit;
    }

    /*Reattempt call with correct buffer size*/
    if (ERROR_BUFFER_OVERFLOW == adapterInfoStatus)
    {
        if (NULL != pIpAdapterInfo)
        {
            free(pIpAdapterInfo);
            pIpAdapterInfo = NULL;
        }
        /*This time allocate memory with the needed buffer size*/
        pIpAdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
        if (NULL == pIpAdapterInfo)
        {
            DB_PRINT("win32_rtos: Error allocating memory needed to call GetAdaptersinfo\n");
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        /*Reattempt call*/
        adapterInfoStatus = GetAdaptersInfo(pIpAdapterInfo, &dwBufLen);
        if (NO_ERROR != adapterInfoStatus || NULL == pIpAdapterInfo)
        {
            DB_PRINT("win32_rtos: Error calling GetAdaptersinfo. Received error = %lu\n", adapterInfoStatus);
            status = ERR_GENERAL;
            goto exit;
        }
    }

    /*Iterate through the chain of adapterinfo received*/
    pAdapterInfo = pIpAdapterInfo;
    do
    {
        if (DIGI_STRNICMP(pAdapterInfo->Description, ifname, DIGI_STRLEN(ifname)) == 0)
        {
            for (iterator = 0; iterator < len; iterator++)
                macAddr[iterator] = pAdapterInfo->Address[iterator];
            DB_PRINT("win32_rtos: Identified MAC address as: %s\n", macAddr);
            if(pAdapterInfo->AdapterName != NULL)
            {
                sbyte4 adapter_len = DIGI_STRLEN(pAdapterInfo->AdapterName);
                DIGI_MEMCPY(adapter_name, pAdapterInfo->AdapterName, adapter_len);
                DB_PRINT("win32_rtos: Identified Adapter name as: %s\n", adapter_name);
            }
            else
                DB_PRINT("win32_rtos: Adapter name is null!!\n");
            status = OK;
            break;
        }
        pAdapterInfo = pAdapterInfo->Next;
    } while (pAdapterInfo);

exit:
    if(NULL != pIpAdapterInfo)
        free(pIpAdapterInfo);

    return status;
}


/*------------------------------------------------------------------*/
/**
* @brief Function to retrieve HW MAC address
* @note In param macAddr should point to memory of minimum size 6 to hold a MAC address value
*/
MOC_EXTERN MSTATUS
WIN32_getHwAddr(ubyte *macAddr, ubyte4 len)
{
    MSTATUS status = ERR_GENERAL;
    PIP_ADAPTER_INFO pIpAdapterInfo = NULL;
    DWORD dwBufLen = sizeof(pIpAdapterInfo);    /*Temporary buffer size until the actual is computed*/
    unsigned long adapterInfoStatus = NO_ERROR;
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ubyte4 iterator;

    /*MAC address value needs 48 bit to fit*/
    if (NULL == macAddr || 6 > len)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    pIpAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (NULL == pIpAdapterInfo) 
    {
        DB_PRINT("win32_rtos: Error allocating memory needed to call GetAdaptersinfo\n");
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /*Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable*/
    adapterInfoStatus = GetAdaptersInfo(pIpAdapterInfo, &dwBufLen);
    if (NO_ERROR != adapterInfoStatus && ERROR_BUFFER_OVERFLOW != adapterInfoStatus)
    {
        DB_PRINT("win32_rtos: Error calling GetAdaptersinfo. Received error = %lu\n", adapterInfoStatus);
        status = ERR_GENERAL;
        goto exit;
    }

    /*Reattempt call with correct buffer size*/
    if (ERROR_BUFFER_OVERFLOW == adapterInfoStatus)
    {
        if (NULL != pIpAdapterInfo)
        {
            free(pIpAdapterInfo);
            pIpAdapterInfo = NULL;
        }
        /*This time allocate memory with the needed buffer size*/
        pIpAdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
        if (NULL == pIpAdapterInfo) 
        {
            DB_PRINT("win32_rtos: Error allocating memory needed to call GetAdaptersinfo\n");
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        /*Reattempt call*/
        adapterInfoStatus = GetAdaptersInfo(pIpAdapterInfo, &dwBufLen);
        if (NO_ERROR != adapterInfoStatus || NULL == pIpAdapterInfo)
        {
            DB_PRINT("win32_rtos: Error calling GetAdaptersinfo. Received error = %lu\n", adapterInfoStatus);
            status = ERR_GENERAL;
            goto exit;
        }
    }
    
    /*Iterate through the chain of adapterinfo received*/
    pAdapterInfo = pIpAdapterInfo; 
    do 
    {
        if (MIB_IF_TYPE_ETHERNET == pAdapterInfo->Type)
        {
            for (iterator = 0; iterator < len; iterator++)
                macAddr[iterator] = pAdapterInfo->Address[iterator];

            DB_PRINT("win32_rtos: Identified MAC address as: %s", macAddr);
            status = OK;
            break;
        }    
        pAdapterInfo = pAdapterInfo->Next;
    } while (pAdapterInfo);

exit:
    if(NULL != pIpAdapterInfo)
        free(pIpAdapterInfo);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS WIN32_lockFileCreate(char *pLockFile, RTOS_LOCK *ppLock)
{
    MSTATUS status;
    int fd;
    int *pLock = NULL;

    if ( (NULL == pLockFile) || (NULL == ppLock) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    fd = _open(pLockFile, _O_RDWR | _O_CREAT, 0660);
    if (0 > fd)
    {
        status = ERR_RTOS_LOCK_CREATE;
        goto exit;
    }

    status = DIGI_MALLOC((void **) ppLock, sizeof(int));
    if (OK != status)
    {
        goto exit;
    }

    *((int *)(*ppLock)) = fd;

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS WIN32_lockFileAcquire(RTOS_LOCK pLock)
{
    MSTATUS status;
    int ret;

    if (NULL == pLock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    do
    {
        ret = _locking(*((int *)pLock), _LK_LOCK, 0);
        if ( (0 != ret) && (EDEADLOCK != errno) )
        {
            status = ERR_RTOS_LOCK_ACQUIRE;
            goto exit;
        }

    } while (0 != ret);

    status = OK;

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS WIN32_lockFileRelease(RTOS_LOCK pLock)
{
    MSTATUS status;

    if (NULL == pLock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 != _locking(*((int *)pLock), _LK_UNLCK, 0))
    {
        status = ERR_RTOS_LOCK_RELEASE;
        goto exit;
    }

    status = OK;

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS WIN32_lockFileFree(RTOS_LOCK *ppLock)
{
    MSTATUS status;

    if ( (NULL == ppLock) || (NULL == *ppLock) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    (void) _close(*((int *)(*ppLock)));
    status = DIGI_FREE(ppLock);

exit:

    return status;
}

#endif /* __RTOS_WIN32__ */
