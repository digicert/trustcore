/*
 * freebsd_rtos.c
 *
 * FreeBSD RTOS Abstraction Layer
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

#ifdef __FREEBSD_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <pthread.h>

#include <stdio.h>
#include <sys/time.h>
#include <sys/times.h>
#include <limits.h>
#include <errno.h>
#include <time.h>

#define NANOS 1000000000
#define MS    1000
#define NANOS_PER_MS     (NANOS / MS)
#define _REENTRANT


/*------------------------------------------------------------------*/

extern MSTATUS
FREEBSD_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREEBSD_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREEBSD_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
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
FREEBSD_mutexWait(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_lock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREEBSD_mutexRelease(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_unlock(pPthreadMutex))))
         status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREEBSD_mutexFree(RTOS_MUTEX* pMutex)
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
FREEBSD_getUpTimeInMS(void)
{
    struct tms tstruct;
    clock_t uptime;
    ubyte4 ms;

    uptime=times(&tstruct);

    if (uptime==-1)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "ERROR: Could not get time values.");
        return -1;
    }

    ms = uptime * (1000 / CLK_TCK);

    return ms;
}


/*------------------------------------------------------------------*/

extern ubyte4
FREEBSD_deltaMS(const moctime_t* origin, moctime_t* current)
{
    struct timeval tval;
    ubyte4 retVal = 0;

    gettimeofday(&tval, NULL);

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

extern ubyte4
FREEBSD_deltaConstMS(const moctime_t* origin, const moctime_t* current)
{
    struct timeval diff;

    diff.tv_sec  = (sbyte4)(current->u.time[0] - origin->u.time[0]);
    diff.tv_usec = (sbyte4)(current->u.time[1] - origin->u.time[1]);

    while ( diff.tv_usec < 0 && diff.tv_sec > 0)
    {
        diff.tv_usec += 1000000;
        diff.tv_sec--;
    }

    /* belt ... */
    if ( diff.tv_usec < 0) diff.tv_usec = 0;

    /* ... and suspenders */
    if ( diff.tv_sec < 0) diff.tv_sec = 0;

    return (diff.tv_sec * 1000 + diff.tv_usec / 1000);
}


/*------------------------------------------------------------------*/

extern moctime_t *
FREEBSD_timerAddMS(moctime_t* pTimer, ubyte4 addNumMS)
{
    pTimer->u.time[0] = pTimer->u.time[0] + (1000 * addNumMS);

    while (pTimer->u.time[0] > 1000000)
    {
        pTimer->u.time[0] -= 1000000;
        pTimer->u.time[1]++;
    }

    return pTimer;
}


/*------------------------------------------------------------------*/

extern void
FREEBSD_sleepMS(ubyte4 sleepTimeInMS)
{
    struct timespec nanopause;

    nanopause.tv_sec = sleepTimeInMS / MS;
    nanopause.tv_nsec = (sleepTimeInMS - (nanopause.tv_sec * MS)) * NANOS_PER_MS;

    nanosleep(&nanopause,0);
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREEBSD_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD* pRetTid)
{
    int         i;
    pthread_t   tid;
    int         ret;
    MSTATUS     status  = OK;

    /* threadType is ignored for this platform, use default values */

    if (0 > (ret = pthread_create(&tid, NULL, (void *(*)(void *))threadEntry, context)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "FREEBSD_createThread: pthread_create error ", ret);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    *pRetTid = tid;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
FREEBSD_destroyThread(RTOS_THREAD tid)
{
    pthread_detach( tid); /* mark the thread for deletion */
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREEBSD_timeGMT(TimeDate* td)
{
    time_t      currentTime = time(NULL);
    struct tm*  pCurrentTime = gmtime(&currentTime);

    if (NULL == td)
        return ERR_NULL_POINTER;

    td->m_year   = (ubyte)(pCurrentTime->tm_year - 70);
    td->m_month  = (ubyte)pCurrentTime->tm_mon + 1; /* 1..12 and gmtime returns 0.11 */;
    td->m_day    = (ubyte)pCurrentTime->tm_mday;
    td->m_hour   = (ubyte)pCurrentTime->tm_hour;
    td->m_minute = (ubyte)pCurrentTime->tm_min;
    td->m_second = (ubyte)pCurrentTime->tm_sec;

    return OK;
}

#endif /* __FREEBSD_RTOS__ */
