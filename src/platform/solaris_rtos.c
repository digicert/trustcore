/*
 * solaris_rtos.c
 *
 * Solaris RTOS Abstraction Layer
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

#ifdef __SOLARIS_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <pthread.h>
#include <thread.h>

#include <stdio.h>
#include <sys/times.h>
#include <limits.h>
#include <errno.h>
#include <time.h>


#define NANOS 1000000000
#define _REENTRANT

static mutex_t m_Mutex;


/*------------------------------------------------------------------*/

extern MSTATUS
SOLARIS_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SOLARIS_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SOLARIS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    mutex_t*    pMutex_t;
    MSTATUS     status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pMutex_t = MALLOC(sizeof(mutex_t))))
        goto exit;

    DIGI_MEMSET((ubyte *)pMutex_t, 0x00, sizeof(mutex_t));

    if (!(0 > mutex_init(pMutex_t, USYNC_THREAD, NULL)))
    {
        *pMutex = (RTOS_MUTEX)pMutex_t;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SOLARIS_mutexWait(RTOS_MUTEX mutex)
{
    mutex_t* pMutex_t = (mutex_t *)mutex;
    MSTATUS  status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pMutex_t) && (!(0 > mutex_lock(pMutex_t))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SOLARIS_mutexRelease(RTOS_MUTEX mutex)
{
    mutex_t* pMutex_t = (mutex_t *)mutex;
    MSTATUS  status = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pMutex_t) && (!(0 > mutex_unlock(pMutex_t))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SOLARIS_mutexFree(RTOS_MUTEX* pMutex)
{
    mutex_t*    pMutex_t;
    MSTATUS     status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    pMutex_t = (mutex_t *)(*pMutex);

    if (!(0 > mutex_destroy(&m_Mutex)))
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
SOLARIS_getUpTimeInMS(void)
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
SOLARIS_deltaMS(const moctime_t* origin, moctime_t* current)
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

extern ubyte4
SOLARIS_deltaConstMS(const moctime_t* origin, const moctime_t* current)
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
SOLARIS_timerAddMS(moctime_t* pTimer, ubyte4 addNumMS)
{
    ubyte4 sec;

    sec = addNumMS / 1000;
    addNumMS %= 1000;

    pTimer->u.time[0] += sec;
    pTimer->u.time[1] += (1000 * addNumMS);

    while (pTimer->u.time[1] > 1000000)
    {
        pTimer->u.time[1] -= 1000000;
        pTimer->u.time[0]++;
    }

    return pTimer;
}


/*------------------------------------------------------------------*/

extern void
SOLARIS_sleepMS(ubyte4 sleepTimeInMS)
{
    struct timespec nanopause;

    nanopause.tv_sec = sleepTimeInMS / 1000;
    nanopause.tv_nsec = 1000000 * (sleepTimeInMS % 1000);

    nanosleep(&nanopause,0);
}


/*------------------------------------------------------------------*/

extern MSTATUS
SOLARIS_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    int i;
    thread_t tid;

    /* threadType is ignored for this platform, use default values */

    thr_create(NULL, 0, (void *(*)(void *))threadEntry, context, 0, &tid);

    *pRetTid = tid;

    return OK;
}


/*------------------------------------------------------------------*/

extern void
SOLARIS_destroyThread(RTOS_THREAD tid)
{
    pthread_detach(tid); /* mark the thread for deletion */
}


/*------------------------------------------------------------------*/

extern sbyte4
SOLARIS_currentThreadId()
{
    return (sbyte4) pthread_self();
}


/*------------------------------------------------------------------*/

extern MSTATUS
SOLARIS_timeGMT(TimeDate* td)
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

#endif /* __SOLARIS_RTOS__ */
