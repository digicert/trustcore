/*
 * symbian_rtos.c
 *
 * Symbian RTOS Abstraction Layer
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

#ifdef __SYMBIAN_RTOS__

#define _XOPEN_SOURCE 500

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/times.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#define NANOS 1000000000
#define _REENTRANT



/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
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
SYMBIAN_mutexWait(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_lock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_mutexRelease(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_unlock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_mutexFree(RTOS_MUTEX* pMutex)
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
SYMBIAN_getUpTimeInMS(void)
{

    struct tms tstruct;
    clock_t    uptime;
    ubyte4     ms;

    uptime=clock();

    if (uptime==-1)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "ERROR: Could not get time values.");
        return -1;
    }

    ms = (uptime*1000)/sysconf(_SC_CLK_TCK);

    return ms;

}


/*------------------------------------------------------------------*/

extern ubyte4
SYMBIAN_deltaMS(const moctime_t* origin, moctime_t* current)
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

        /* on some platforms (multiCPU), gettimeofday is not monotonic
           the number of nanoseconds can be lower than on a previous call.
           fortunately it seems the number of seconds stays the same in
           that case so we can prepare for that */
        while ( diff.tv_usec < 0 && diff.tv_sec > 0)
        {
            diff.tv_usec += 1000000;
            diff.tv_sec--;
        }
        /* belt ... */
        if ( diff.tv_usec < 0) diff.tv_usec = 0;
        /* ... and suspenders */
        if ( diff.tv_sec < 0) diff.tv_sec = 0;

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
SYMBIAN_deltaConstMS(const moctime_t* origin, const moctime_t* current)
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
SYMBIAN_timerAddMS(moctime_t* pTimer, ubyte4 addNumMS)
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
SYMBIAN_sleepMS(ubyte4 sleepTimeInMS)
{
    struct timespec nanopause;

    nanopause.tv_sec = sleepTimeInMS / 1000;
    nanopause.tv_nsec = 1000000 * (sleepTimeInMS % 1000);

    nanosleep(&nanopause,0);
}


/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    pthread_t   tid;
    int         ret;
    MSTATUS     status  = OK;

    /* threadType is ignored for this platform, use default values */

    if (0 > (ret = pthread_create(&tid, NULL, (void *(*)(void *))threadEntry, context)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "SYMBIAN_createThread: pthread_create error ", ret);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    *pRetTid = (RTOS_THREAD)tid;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
SYMBIAN_destroyThread(RTOS_THREAD tid)
{
    pthread_detach( (pthread_t)tid); /* mark the thread for deletion */
}


/*------------------------------------------------------------------*/

extern sbyte4
SYMBIAN_currentThreadId()
{
    /* FIXME: will not work on 64 bit platforms */
    return (sbyte4) pthread_self();
}


/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_timeGMT(TimeDate* td)
{
    time_t      currentTime = time(NULL);
    struct tm*  pCurrentTime = gmtime(&currentTime);

    if (NULL == td)
        return ERR_NULL_POINTER;

    td->m_year   = (ubyte)(pCurrentTime->tm_year - 70);
    td->m_month  = (ubyte)pCurrentTime->tm_mon+ 1; /* 1..12 and gmtime returns 0.11 */
    td->m_day    = (ubyte)pCurrentTime->tm_mday;
    td->m_hour   = (ubyte)pCurrentTime->tm_hour;
    td->m_minute = (ubyte)pCurrentTime->tm_min;
    td->m_second = (ubyte)pCurrentTime->tm_sec;

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_condCreate(RTOS_COND* pCond, enum mutexTypes mutexType, int mutexCount)
{
    pthread_cond_t* pPthreadCond;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pPthreadCond = MALLOC(sizeof(pthread_cond_t))))
        goto exit;

    DIGI_MEMSET((ubyte *)pPthreadCond, 0x00, sizeof(pthread_cond_t));

    if (!(0 > pthread_cond_init(pPthreadCond, NULL)))
    {
        *pCond = (RTOS_MUTEX)pPthreadCond;
        status = OK;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_condWait(RTOS_COND cond, RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    pthread_cond_t*  pPthreadCond  = (pthread_cond_t *)cond;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (NULL != pPthreadCond) && (!(0 > pthread_cond_wait(pPthreadCond,pPthreadMutex))))
        status = OK;

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_condSignal(RTOS_COND cond)
{
    pthread_cond_t* pPthreadCond = (pthread_cond_t *)cond;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadCond) && (!(0 > pthread_cond_signal(pPthreadCond))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SYMBIAN_condFree(RTOS_COND* pCond)
{
    pthread_cond_t* pPthreadCond;
    MSTATUS          status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pCond) || (NULL == *pCond))
        goto exit;

    pPthreadCond = (pthread_cond_t *)(*pCond);

    if (!(0 > pthread_cond_destroy(pPthreadCond)))
    {
        FREE(*pCond);
        *pCond = NULL;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

#endif /* __SYMBIAN_RTOS__ */
