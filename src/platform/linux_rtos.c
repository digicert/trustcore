/*
 * linux_rtos.c
 *
 * Linux RTOS Abstraction Layer
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

#if defined(__LINUX_RTOS__) || defined (__ANDROID_RTOS__)

#define _GNU_SOURCE
#define _XOPEN_SOURCE 500

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#if defined(__LINUX_RTOS__)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <stdio.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <linux/sockios.h>
#include <string.h>
#endif

#include <unistd.h>
#include <fcntl.h>
#include <semaphore.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/times.h>
#include <limits.h>
#include <errno.h>
#include <time.h>

#ifndef __WR_LINUX__
#include <asm/param.h>
#endif
#define NANOS 1000000000

#ifndef _REENTRANT
#define _REENTRANT
#endif



/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    pthread_mutex_t* pPthreadMutex;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pPthreadMutex = (pthread_mutex_t*) MALLOC(sizeof(pthread_mutex_t))))
        goto exit;

    MOC_MEMSET((ubyte *)pPthreadMutex, 0x00, sizeof(pthread_mutex_t));

    if (!(0 > pthread_mutex_init(pPthreadMutex, NULL)))
    {
        *pMutex = (RTOS_MUTEX)pPthreadMutex;
        status = OK;
    }
    else
        FREE (pPthreadMutex);  /* free unused pointer */

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_mutexWait(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_lock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_mutexWaitEx(RTOS_MUTEX mutex, ubyte4 timeoutMs)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;
    struct timespec t = {0};

    if (NULL == pPthreadMutex)
    {
        return status;
    }

    /* Get the current time */
    if (0 != clock_gettime(CLOCK_REALTIME, &t))
    {
        return status;
    }

    /* For now all callers call with wait times in even seconds */
    t.tv_sec += (timeoutMs / 1000);

    if (0 != pthread_mutex_timedlock(pPthreadMutex, (const struct timespec *)&t))
    {
        return ERR_RTOS_SEM_WAIT;
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_mutexRelease(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_unlock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_mutexFree(RTOS_MUTEX* pMutex)
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

#ifdef __ENABLE_MOCANA_GLOBAL_MUTEX__
/*------------------------------------------------------------------*/
extern MSTATUS
LINUX_globalMutexCreate(char *mutexName, RTOS_GLOBAL_MUTEX* ppMutex)
{
    MSTATUS status = OK;
    sem_t *semDesc;

    /* sem_unlink(mutexName); */

    if ((semDesc = sem_open(mutexName, O_CREAT, 0666, 1)) == SEM_FAILED)
    {
        status = ERR_RTOS_MUTEX_CREATE;
        goto exit;
    }

    *ppMutex = (RTOS_GLOBAL_MUTEX)semDesc;

exit:
    return status;
}

/*------------------------------------------------------------------*/
extern MSTATUS
LINUX_globalMutexWait(RTOS_GLOBAL_MUTEX pMutex, ubyte4 timeoutInSecs)
{
    MSTATUS status = OK;
    sem_t *semDesc = NULL;
    ubyte4 timeoutInMSec = timeoutInSecs*1000;

    if (NULL != pMutex)
    {
        semDesc = (sem_t *)pMutex;
        if (timeoutInMSec)
        {
            do
            {
                if (!sem_trywait(semDesc))
                    break;

                if (EAGAIN != errno)
                {
                    status = ERR_RTOS_MUTEX_WAIT;
                    break;
                }

                /* Sleep for 1 millisecond */
                LINUX_sleepMS(1);

                timeoutInMSec--;
            } while (timeoutInMSec);
        }
        else
        {
            if(sem_wait(semDesc))
                status = ERR_RTOS_MUTEX_WAIT;
        }
    }
    else
        status = ERR_RTOS_MUTEX_WAIT;
    return status;
}

/*------------------------------------------------------------------*/
extern MSTATUS
LINUX_globalMutexRelease(RTOS_GLOBAL_MUTEX pMutex)
{
    MSTATUS status = OK;
    sem_t *semDesc;

    if (NULL != pMutex)
    {
        semDesc = (sem_t *)pMutex;
        if(sem_post(semDesc))
            status = ERR_RTOS_MUTEX_RELEASE;
    }
    else
        status = ERR_RTOS_MUTEX_RELEASE;

    return status;
}

/*------------------------------------------------------------------*/
extern MSTATUS
LINUX_globalMutexFree(char *mutexName, RTOS_GLOBAL_MUTEX* ppMutex)
{
    MSTATUS status = ERR_RTOS_MUTEX_FREE;
    sem_t *semDesc;

    if ((NULL == ppMutex) || (NULL == *ppMutex))
        goto exit;

    semDesc = (sem_t *)(*ppMutex);

    sem_close(semDesc);
    sem_unlink(mutexName);

    status = OK;

exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

extern ubyte4
LINUX_getUpTimeInMS(void)
{
    struct tms tstruct;
    clock_t    uptime;
    ubyte4     ms;

    uptime=times(&tstruct);

    if (uptime==-1)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"ERROR: Could not get time values.");
        return -1;
    }

    ms = (uptime*1000)/sysconf(_SC_CLK_TCK);

    return ms;
}


/*------------------------------------------------------------------*/

extern ubyte4
LINUX_deltaMS(const moctime_t* origin, moctime_t* current)
{
    struct timeval tval;
    ubyte4 retVal = 0;

    (void) gettimeofday(&tval, NULL);

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
LINUX_deltaConstMS(const moctime_t* origin, const moctime_t* current)
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

extern sbyte4
LINUX_timeCompare(const moctime_t *t1, const moctime_t *t2)
{
    struct timeval diff;

    diff.tv_sec  = (sbyte4)(t1->u.time[0] - t2->u.time[0]);
    diff.tv_usec = (sbyte4)(t1->u.time[1] - t2->u.time[1]);

    while (diff.tv_sec < 0 && diff.tv_usec > 0)
    {
        diff.tv_usec -= 1000000;
        diff.tv_sec++;
    }

    if (diff.tv_sec < 0) return -1;

    while (diff.tv_sec > 0 && diff.tv_usec < 0)
    {
        diff.tv_usec += 1000000;
        diff.tv_sec--;
    }

    if (diff.tv_sec > 0) return 1;

    if (diff.tv_usec < 0) return -1;
    else if (diff.tv_usec > 0) return 1;

    return 0;
}


/*------------------------------------------------------------------*/

extern moctime_t *
LINUX_timerAddMS(moctime_t* pTimer, ubyte4 addNumMS)
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

extern intBoolean
LINUX_sleepCheckStatusMS(ubyte4 sleepTimeInMS)
{
    struct timespec nanopause;

    nanopause.tv_sec = sleepTimeInMS / 1000;
    nanopause.tv_nsec = 1000000 * (sleepTimeInMS % 1000);

    /*
       On successfully sleeping for the requested duration, nanosleep()
       returns 0.  If the call is interrupted by a signal handler or
       encounters an error, then it returns -1, with errno set to
       indicate the error.
    */
    if (-1 == nanosleep(&nanopause,0)) return FALSE;
    return TRUE;
}


/*------------------------------------------------------------------*/

extern void
LINUX_sleepMS(ubyte4 sleepTimeInMS)
{
    struct timespec nanopause;

    nanopause.tv_sec = sleepTimeInMS / 1000;
    nanopause.tv_nsec = 1000000 * (sleepTimeInMS % 1000);

    (void) nanosleep(&nanopause,0);
}


/*------------------------------------------------------------------*/

#pragma GCC diagnostic ignored "-Wcast-function-type"
extern MSTATUS
LINUX_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    pthread_t   tid;
    int         ret;
    MSTATUS     status  = OK;

    /* threadType is ignored for this platform, use default values */

    if (0 > (ret = pthread_create(&tid, NULL, (void *(*)(void *))threadEntry, context)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_createThread: pthread_create error ", ret);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    *pRetTid = (RTOS_THREAD)tid;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
LINUX_destroyThread(RTOS_THREAD tid)
{
    (void) pthread_detach((pthread_t) tid); /* mark the thread for deletion */
}

/*------------------------------------------------------------------*/

extern void
LINUX_exitThread(void *pRetVal)
{
    pthread_exit(pRetVal);
}

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_joinThread(RTOS_THREAD tid, void **ppRetVal)
{
    if (0 == pthread_join((pthread_t) tid, ppRetVal))
        return OK;
    else
        return ERR_RTOS_THREAD_JOIN;
}

/*------------------------------------------------------------------*/

extern RTOS_THREAD
LINUX_currentThreadId(void)
{
    return (RTOS_THREAD) pthread_self();
}


/*------------------------------------------------------------------*/

extern intBoolean
LINUX_sameThreadId(RTOS_THREAD tid1, RTOS_THREAD tid2)
{
    return (pthread_equal((pthread_t)tid1, (pthread_t)tid2) ? TRUE : FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_timeGMT(TimeDate* td)
{
    time_t      currentTime = time(NULL);
    struct tm*  pCurrentTime = gmtime(&currentTime);

    if (NULL == td)
        return ERR_NULL_POINTER;

    if (NULL == pCurrentTime)
        return ERR_RTOS_GMT_TIME_NOT_AVAILABLE;

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
LINUX_condCreate(RTOS_COND* pCond, enum mutexTypes mutexType, int mutexCount)
{
    pthread_cond_t* pPthreadCond;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pPthreadCond = (pthread_cond_t*) MALLOC(sizeof(pthread_cond_t))))
        goto exit;

    MOC_MEMSET((ubyte *)pPthreadCond, 0x00, sizeof(pthread_cond_t));

    if (!(0 > pthread_cond_init(pPthreadCond, NULL)))
    {
        *pCond = (RTOS_MUTEX)pPthreadCond;
        status = OK;
    }
    else
        FREE (pPthreadCond);  /* free unused pointer */

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_condWait(RTOS_COND cond, RTOS_MUTEX mutex)
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
LINUX_condTimedWait(RTOS_COND cond, RTOS_MUTEX mutex, ubyte4 timeoutMS, byteBoolean *pTimeout)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    pthread_cond_t*  pPthreadCond  = (pthread_cond_t *)cond;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;
    struct timespec timeToWait = { 0 };
    int ret;
    struct timespec now = { 0 };

    if (NULL == pTimeout || NULL == pPthreadMutex || NULL == pPthreadCond)
        return ERR_NULL_POINTER;

    *pTimeout = FALSE;

    clock_gettime(CLOCK_REALTIME, &now);
    timeToWait.tv_sec = now.tv_sec + (timeoutMS / 1000);
    if (timeoutMS % 1000)
    {
        timeToWait.tv_sec++;
    }

    ret = pthread_cond_timedwait(pPthreadCond,pPthreadMutex,&timeToWait);
    if (0 == ret)
    {
        status = OK;
    }
    else if (ETIMEDOUT == ret)
    {
        status = OK;
        *pTimeout = TRUE;
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_condSignal(RTOS_COND cond)
{
    pthread_cond_t* pPthreadCond = (pthread_cond_t *)cond;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadCond) && (!(0 > pthread_cond_signal(pPthreadCond))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_condFree(RTOS_COND* pCond)
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

typedef struct
{
    pthread_mutex_t shared;
    pthread_cond_t  readerQ;
    pthread_cond_t  writerQ;
    ubyte4          active_readers;
    ubyte4          waiting_writers;
    intBoolean      active_writer;
    pthread_t       active_writer_tid;

} LINUX_rw_lock;

extern MSTATUS
LINUX_rwLockCreate(RTOS_RWLOCK* ppLock)
{
    LINUX_rw_lock* pLock;
    MSTATUS        status = ERR_RTOS_MUTEX_CREATE;

    if (NULL == (pLock = (LINUX_rw_lock*) MALLOC(sizeof(LINUX_rw_lock))))
        goto exit;

    MOC_MEMSET((ubyte *)pLock, 0x00, sizeof(LINUX_rw_lock));

    if (0 > pthread_mutex_init(&pLock->shared, NULL))
    {
        goto exit;
    }
    if (0 > pthread_cond_init(&pLock->readerQ, NULL))
    {
        pthread_mutex_destroy(&pLock->shared);
        goto exit;
    }
    if (0 > pthread_cond_init(&pLock->writerQ, NULL))
    {
        pthread_cond_destroy(&pLock->readerQ);
        pthread_mutex_destroy(&pLock->shared);
        goto exit;
    }

    *ppLock = (RTOS_RWLOCK)pLock;
    pLock = NULL;
    status = OK;

exit:
    if (pLock) FREE(pLock);
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_rwLockWaitR(RTOS_RWLOCK lock)
{
    LINUX_rw_lock* pLock = (LINUX_rw_lock *)lock;
    MSTATUS        status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL == pLock) || (0 > pthread_mutex_lock(&pLock->shared)))
        goto exit;

    while (pLock->waiting_writers)
    {
        if (0 > pthread_cond_wait(&pLock->readerQ, &pLock->shared))
        {
            pthread_mutex_unlock(&pLock->shared);
            goto exit;
        }
    }

    ++(pLock->active_readers);

    if (0 > pthread_mutex_unlock(&pLock->shared))
        goto exit;

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_rwLockReleaseR(RTOS_RWLOCK lock)
{
    LINUX_rw_lock* pLock = (LINUX_rw_lock *)lock;
    MSTATUS        status = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL == pLock) || (0 > pthread_mutex_lock(&pLock->shared)))
        goto exit;

    if (pLock->active_readers) /* jic */
        --(pLock->active_readers);

    if (0 > pthread_mutex_unlock(&pLock->shared))
        goto exit;

    if (0 > pthread_cond_signal(&pLock->writerQ))
        goto exit;

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_rwLockWaitW(RTOS_RWLOCK lock)
{
    LINUX_rw_lock* pLock = (LINUX_rw_lock *)lock;
    MSTATUS        status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL == pLock) || (0 > pthread_mutex_lock(&pLock->shared)))
        goto exit;

    ++(pLock->waiting_writers);

    while (pLock->active_readers || pLock->active_writer)
    {
        if (0 > pthread_cond_wait(&pLock->writerQ, &pLock->shared))
        {
            pthread_mutex_unlock(&pLock->shared);
            goto exit;
        }
    }

    pLock->active_writer = TRUE;
    pLock->active_writer_tid = pthread_self();

    if (0 > pthread_mutex_unlock(&pLock->shared))
        goto exit;

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_rwLockReleaseW(RTOS_RWLOCK lock)
{
    LINUX_rw_lock* pLock = (LINUX_rw_lock *)lock;
    MSTATUS        status = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL == pLock) || (0 > pthread_mutex_lock(&pLock->shared)))
        goto exit;

    if (pLock->waiting_writers) /* jic */
    {
        --(pLock->waiting_writers);
        pLock->active_writer = FALSE;
    }

    if (pLock->waiting_writers)
    {
        if (0 > pthread_cond_signal(&pLock->writerQ))
        {
            pthread_mutex_unlock(&pLock->shared);
            goto exit;
        }
    }
    else
    {
        if (0 > pthread_cond_broadcast(&pLock->readerQ))
        {
            pthread_mutex_unlock(&pLock->shared);
            goto exit;
        }
    }

    if (0 > pthread_mutex_unlock(&pLock->shared))
        goto exit;

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern intBoolean
LINUX_rwLockOwnerW(RTOS_RWLOCK lock)
{
    LINUX_rw_lock* pLock = (LINUX_rw_lock *)lock;
    intBoolean ret = FALSE;

    if ((NULL == pLock) || (0 > pthread_mutex_lock(&pLock->shared)))
        goto exit;

    if (pLock->active_writer &&
        pthread_equal(pthread_self(), pLock->active_writer_tid))
        ret = TRUE;

    pthread_mutex_unlock(&pLock->shared);

exit:
    return ret;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_rwLockFree(RTOS_RWLOCK* ppLock)
{
    LINUX_rw_lock* pLock;
    MSTATUS        status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == ppLock) || (NULL == *ppLock))
        goto exit;

    pLock = (LINUX_rw_lock *)(*ppLock);

    if (0 > pthread_cond_destroy(&pLock->writerQ) ||
        0 > pthread_cond_destroy(&pLock->readerQ) ||
        0 > pthread_mutex_destroy(&pLock->shared))
        goto exit;

    FREE(pLock);
    *ppLock = NULL;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_recursiveMutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    pthread_mutex_t* pPthreadMutex;
    pthread_mutexattr_t attr;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pPthreadMutex = (pthread_mutex_t*) MALLOC(sizeof(pthread_mutex_t))))
        goto exit;

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    MOC_MEMSET((ubyte *)pPthreadMutex, 0x00, sizeof(pthread_mutex_t));

    if (!(0 > pthread_mutex_init(pPthreadMutex, &attr)))
    {
        *pMutex = (RTOS_MUTEX)pPthreadMutex;
        status = OK;
    }
    else
        FREE (pPthreadMutex);  /* free unused pointer */

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_recursiveMutexWait(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_lock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_recursiveMutexRelease(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_unlock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_recursiveMutexFree(RTOS_MUTEX* pMutex)
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

#if defined(__LINUX_RTOS__)
#ifdef __RTOS_LINUX__
extern MSTATUS
LINUX_getHwAddrByIfname(const sbyte *ifname, sbyte *adapter_name, ubyte *macAddr, ubyte4 len)
{
    MSTATUS status = ERR_GENERAL;
    MOC_UNUSED(adapter_name);
    int s;
    ubyte4 macAddrFound = 0;
    struct ifreq ifr;

    if (-1 == (s = socket(AF_INET, SOCK_DGRAM, 0)))
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DB_PRINT("Error: %s opening socket to query for interface mac address\n", strerror(errno));
#endif
        goto exit;
    }
    memset(&ifr, 0, sizeof(ifr));

    (void) MOC_STRCBCPY((sbyte *)ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

    if (-1 != ioctl(s, SIOCGIFHWADDR, &ifr))
    {
        MOC_MEMCPY(macAddr, ifr.ifr_hwaddr.sa_data, len > IFHWADDRLEN ? IFHWADDRLEN : len);
        macAddrFound = 1;
        status = OK;
    }
    else
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DB_PRINT("Error: %s issuing ioctl to interface: %s", strerror(errno), ifr.ifr_name);
#endif
        status = ERR_GENERAL;
    }

    if (!macAddrFound)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DB_PRINT("Error: Could not find a Running/Non-Loopback ethernet interface\n");
#endif
        status = ERR_GENERAL;
    }
exit:
    if (-1 != s)
        (void) close(s);

    return status;
}
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_getHwAddr(ubyte *macAddr, ubyte4 len)
{
    MSTATUS status = ERR_GENERAL;
    int s;
    ubyte4 macAddrFound = 0;
    struct ifreq ifr;
    struct ifaddrs *ifaddr, *ifstart;

    if (-1 == (s = socket(AF_INET, SOCK_DGRAM, 0)))
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DB_PRINT("Error: %s opening socket to query for interface mac address\n", strerror(errno));
#endif
        goto exit;
    }

    if (!getifaddrs(&ifaddr))
    {
        ifstart = ifaddr;
        do {
            /* Interfaces repeat for other address families */
            if (!ifaddr->ifa_data)
                break;

            if (!(ifaddr->ifa_flags & IFF_LOOPBACK) && (ifaddr->ifa_flags & IFF_RUNNING))
            {
                memset(&ifr, 0, sizeof(ifr));

                (void) MOC_STRCBCPY((sbyte *)ifr.ifr_name, sizeof(ifr.ifr_name), (const sbyte *)ifaddr->ifa_name);

                if (-1 != ioctl(s, SIOCGIFHWADDR, &ifr))
                {
                    MOC_MEMCPY(macAddr, ifr.ifr_hwaddr.sa_data, len > IFHWADDRLEN ? IFHWADDRLEN : len);
                    macAddrFound = 1;
                    status = OK;
                    break;
                }
                else
                {
#ifdef __ENABLE_ALL_DEBUGGING__
                    DB_PRINT("Error: %s issuing ioctl to interface: %s", strerror(errno), ifr.ifr_name);
#endif
                    status = ERR_GENERAL;
                }
            }

            ifaddr = ifaddr->ifa_next;
        } while (ifaddr);

        freeifaddrs(ifstart);
    }

    if (!macAddrFound)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DB_PRINT("Error: Could not find a Running/Non-Loopback ethernet interface\n");
#endif
        status = ERR_GENERAL;
    }
exit:
    if (-1 != s)
        (void) close(s);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_semCreate(RTOS_SEM *pSem, sbyte4 initialValue)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pSem)
        goto exit;

    if (NULL == (*pSem = MALLOC(sizeof(sem_t))))
    {
        status = ERR_RTOS_SEM_ALLOC;
        goto exit;
    }

    MOC_MEMSET(*pSem, 0, sizeof(sem_t));

    if (sem_init((sem_t *)*pSem, 0, initialValue) < 0)
    {
        status = ERR_RTOS_SEM_INIT;
        goto exit;
    }

    status = OK;

exit:
    if (OK != status)
    {
        if (pSem && *pSem)
            FREE(*pSem);
    }

    return status;
}


extern MSTATUS
LINUX_semWait(RTOS_SEM sem)
{
    MSTATUS status = OK;

    if (NULL == sem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (sem_wait(sem) < 0)
    {
        if (EINTR == errno)
            status = ERR_RTOS_SEM_CALL_INTR;
        else
            status = ERR_RTOS_SEM_WAIT;
    }
exit:

    return status;
}

extern MSTATUS
LINUX_semTryWait(RTOS_SEM sem)
{
    MSTATUS status = OK;

    if (NULL == sem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (sem_trywait(sem) < 0)
    {
        if (EAGAIN == errno)
            status = ERR_RTOS_SEM_NOT_READY;
        else if (EINTR == errno)
            status = ERR_RTOS_SEM_CALL_INTR;
        else
            status = ERR_RTOS_SEM_WAIT;
    }

exit:

    return status;
}

extern MSTATUS
LINUX_semSignal(RTOS_SEM sem)
{
    MSTATUS status = OK;

    if (NULL == sem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (sem_post(sem) < 0)
        status = ERR_RTOS_SEM_SIGNAL;

exit:

    return status;
}

extern MSTATUS
LINUX_semFree(RTOS_SEM *pSem)
{
    MSTATUS status = OK;

    if ((NULL == pSem) || (NULL == *pSem))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    sem_destroy((sem_t *)*pSem);

    FREE(*pSem);

exit:

    return status;

}

#endif

/*------------------------------------------------------------------*/

extern MSTATUS LINUX_lockFileCreate(char *pLockFile, RTOS_LOCK *ppLock)
{
    MSTATUS status;
    int fd = -1;
    int *pLock = NULL;

    if ( (NULL == pLockFile) || (NULL == ppLock) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    fd = open(pLockFile, O_RDWR | O_CREAT, 0660);
    if (0 > fd)
    {
        status = ERR_RTOS_LOCK_CREATE;
        goto exit;
    }

    status = MOC_MALLOC((void **) ppLock, sizeof(int));
    if (OK != status)
    {
        goto exit;
    }

    *((int *)(*ppLock)) = fd;
    fd = -1;

exit:
    
    if (0 <= fd)
    {
        (void) close(fd);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS LINUX_lockFileAcquire(RTOS_LOCK pLock)
{
    MSTATUS status;

    if (NULL == pLock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 != lockf(*((int *)pLock), F_LOCK, 0))
    {
        status = ERR_RTOS_LOCK_ACQUIRE;
        goto exit;
    }

    status = OK;

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS LINUX_lockFileRelease(RTOS_LOCK pLock)
{
    MSTATUS status;

    if (NULL == pLock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 != lockf(*((int *)pLock), F_ULOCK, 0))
    {
        status = ERR_RTOS_LOCK_RELEASE;
        goto exit;
    }

    status = OK;

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS LINUX_lockFileFree(RTOS_LOCK *ppLock)
{
    MSTATUS status;

    if ( (NULL == ppLock) || (NULL == *ppLock) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    (void) close(*((int *)(*ppLock)));
    status = MOC_FREE(ppLock);

exit:

    return status;
}

#endif /* __LINUX_RTOS__ */
