/*
 * nnos_rtos.c
 *
 * NNOS RTOS Abstraction Layer
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

#define NANOS 1000000000

#include "../common/moptions.h"

#ifdef __NNOS_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <NNstyle.h>
/* #include <nnos.h> */
#include <time.h>
/* #include <tickLib.h> */
/* #include <taskLib.h> */
/* #include <sysLib.h> */
/* #include <semLib.h> */
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/time.h>
#include <pthread.h>


#define _REENTRANT

#ifndef SSH_THREAD_PRIORITY
#define SSH_THREAD_PRIORITY     (100)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    pthread_mutex_t* pPthreadMutex;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pPthreadMutex = MALLOC(sizeof(pthread_mutex_t))))
        goto exit;

    DIGI_MEMSET((ubyte *)pPthreadMutex, 0x00, sizeof(pthread_mutex_t));

    if (!(0 > pthread_mutex_init(pPthreadMutex, NULL)))
    {
        *pMutex = (RTOS_MUTEX)pPthreadMutex;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_mutexWait(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_lock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_mutexRelease(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_unlock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_mutexFree(RTOS_MUTEX* pMutex)
{
    pthread_mutex_t* pPthreadMutex;
    MSTATUS          status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    pPthreadMutex = (pthread_mutex_t *)(*pMutex);

    if (!(0 > pthread_mutex_destroy(pPthreadMutex)))
    {
        FREE(*pMutex);
        *pMutex = NULL;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte4
NNOS_getUpTimeInMS(void)
{
    DWORD dwmsec;
    struct timeval what_time_it_is;

    gettimeofday(&what_time_it_is, NULL);

    dwmsec = (what_time_it_is.tv_usec >> 10);
    dwmsec += (what_time_it_is.tv_sec << 10);

    return dwmsec;
}


/*------------------------------------------------------------------*/

extern ubyte4
NNOS_deltaMS(const moctime_t* origin, moctime_t* current)
{
    struct timeval tval;
    ubyte4 retVal = 0;

    gettimeofday(&tval, NULL);

    /* origin and current can point to the same struct */
    if (origin)
    {
        struct timeval diff;
        diff.tv_sec = tval.tv_sec - ((sbyte4) origin->u.time[0]);
        diff.tv_usec = tval.tv_usec - ((sbyte4) origin->u.time[1]);

        while ( diff.tv_usec < 0 )
        {
            diff.tv_usec += 1000000;
            diff.tv_sec--;
        }

        retVal  = diff.tv_sec * 1000 + diff.tv_usec / 1000;
    }

    if (current)
    {
        current->u.time[0] = tval.tv_sec;
        current->u.time[1] = tval.tv_usec;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
NNOS_sleepMS(ubyte4 sleepTimeInMS)
{

    /* CLOCKS_PER_SEC, the number of ticks per second */
    /* Order is important, prevent rounding errors */

    struct timespec nanopause;
    long long nanoseconds;
    DWORD two = 2;

    nanoseconds = sleepTimeInMS * 1000000;
    nanopause.tv_sec = nanoseconds >> 30;
    nanopause.tv_nsec = nanoseconds & ((two << 30) - 1);

    nanosleep(&nanopause, NULL);
}


/*------------------------------------------------------------------*/

typedef struct
{
  void(*threadEntry)(sbyte4);
  sbyte4   context;

} threadDescr;

static void *
nnosThreadEntry(void *pTempDescr)
{
    threadDescr *pThreadDescr = (threadDescr *)pTempDescr;

    if ((NULL != pThreadDescr) && (NULL != pThreadDescr->threadEntry))
        pThreadDescr->threadEntry(pThreadDescr->context);

    return NULL;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    threadDescr *pThreadDescr = malloc(sizeof(threadDescr));
    MSTATUS status = OK;

    if (NULL == pThreadDescr)
    {
    status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    pThreadDescr->threadEntry = threadEntry;
    pThreadDescr->context = context;

    pthread_create((WORD*)pRetTid, NULL, nnosThreadEntry, (void*)pThreadDescr);

    if (NULL == pRetTid)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "NNOS_createThread: taskSpawn() failed.");
        free(pThreadDescr);
        status = ERR_RTOS_THREAD_CREATE;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
NNOS_destroyThread(RTOS_THREAD tid)
{
    /* Not needed with this OS */
    /* STATUS taskDelete(int tid); */
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_timeGMT(TimeDate* td)
{
#if 0
    SYSTEMTIME sm;

    if (0 == td)
    {
        return ERR_NULL_POINTER;
    }

    GetSystemTime(&sm);

    td->m_year   = sm.wYear - 1970;
    td->m_month  = sm.wMonth;
    td->m_day    = sm.wDay;
    td->m_hour   = sm.wHour;
    td->m_minute = sm.wMinute;
    td->m_second = sm.wSecond;
#endif

    return OK;
}

#endif /* __NNOS_RTOS__ */

