/*
 * QNX_rtos.c
 *
 * GHS QNX RTOS Abstraction Layer
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

#ifdef __QNX_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/times.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <semaphore.h>
#if 0
#include <asm/param.h>
#endif /* TBD */

#define NANOS 1000000000
#define _REENTRANT


/*------------------------------------------------------------------*/

extern MSTATUS
QNX_rtosInit(void)
{
    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
QNX_rtosShutdown(void)
{
    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
QNX_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    sem_t *pNewMutex = NULL;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    status = DIGI_MALLOC((void **)&pNewMutex, sizeof(sem_t));
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET((ubyte *)pNewMutex, 0, sizeof(sem_t));
    if (OK != status)
        goto exit;

    if (0 != sem_init(pNewMutex, 1, 1))
    {
        goto exit;
    }
    else
    {
        status = OK;
        *pMutex = pNewMutex;
        pNewMutex = NULL;
    }

exit:

    if (NULL != pNewMutex)
    {
        DIGI_FREE((void **)&pNewMutex);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
QNX_mutexWait(RTOS_MUTEX mutex)
{
    sem_t *pMutex = (sem_t *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if (NULL == mutex)
        goto exit;

    if (0 != sem_wait(pMutex))
    {
        goto exit;
    }

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
QNX_mutexWaitEx(RTOS_MUTEX mutex, ubyte4 timeoutMs)
{
    sem_t *pMutex = (sem_t *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;
    struct timespec t = {0};

    if (NULL == mutex)
        goto exit;

    if (0 != clock_gettime(CLOCK_REALTIME, &t))
    {
        goto exit;
    }

    /* For now our only caller is from UM_utilWait who originally
     * converted from seconds, so this will always divide evenly */
    t.tv_sec += (time_t)(timeoutMs / 1000);

    if (0 != sem_timedwait(pMutex, &t))
    {
        status = ERR_RTOS_SEM_WAIT;
        goto exit;
    }

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
QNX_mutexRelease(RTOS_MUTEX mutex)
{
    sem_t *pMutex = (sem_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if (NULL == mutex)
        goto exit;

    if (0 != sem_post(pMutex))
    {
        goto exit;
    }

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
QNX_mutexFree(RTOS_MUTEX* ppMutex)
{
    sem_t *pMutex = NULL;
    MSTATUS          status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == ppMutex) || (NULL == *ppMutex))
        goto exit;

    pMutex = (sem_t *)(*ppMutex);
    if (0 != sem_destroy(pMutex))
    {
        DIGI_FREE((void **)&pMutex);
        *ppMutex = NULL;
        goto exit;
    }

    DIGI_FREE((void **)&pMutex);
    *ppMutex = NULL;
    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
QNX_semCreate(RTOS_SEM *pSem, sbyte4 initialValue)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pSem)
        goto exit;

    if (NULL == (*pSem = MALLOC(sizeof(sem_t))))
    {
        status = ERR_RTOS_SEM_ALLOC;
        goto exit;
    }

    DIGI_MEMSET(*pSem, 0, sizeof(sem_t));

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
QNX_semTryWait(RTOS_SEM sem)
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

/*------------------------------------------------------------------*/

extern ubyte4
QNX_getUpTimeInMS(void)
{
    struct tms tstruct;
    clock_t    uptime;
    ubyte4     ms;

    uptime=times(&tstruct);

    if (uptime==-1)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte*)"ERROR: Could not get time values.");
        return -1;
    }

    ms = (uptime*1000.0)/sysconf(_SC_CLK_TCK);

    return ms;

}


/*------------------------------------------------------------------*/

extern ubyte4
QNX_deltaMS(const moctime_t* origin, moctime_t* current)
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
QNX_sleepMS(ubyte4 sleepTimeInMS)
{
    struct timespec nanopause;

    nanopause.tv_sec = sleepTimeInMS / 1000;
    nanopause.tv_nsec = 1000000 * (sleepTimeInMS % 1000);

    nanosleep(&nanopause,0);

}


/*------------------------------------------------------------------*/

extern MSTATUS
QNX_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    pthread_t   tid;
    int         ret;
    MSTATUS     status  = OK;
    pthread_attr_t attr;

    /* threadType is ignored for this platform, use default values */

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 80000);

    if (0 > (ret = pthread_create(&tid, NULL, (void *(*)(void *))threadEntry, (void *)context)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte*)"LINUX_createThread: pthread_create error ", ret);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    *pRetTid = (RTOS_THREAD)tid;

exit:
    return status;

}


/*------------------------------------------------------------------*/

extern void
QNX_destroyThread(RTOS_THREAD tid)
{
    pthread_detach((pthread_t) tid); /* mark the thread for deletion */
}

/*------------------------------------------------------------------*/

extern RTOS_THREAD
QNX_currentThreadId()
{
    return (RTOS_THREAD) pthread_self();
}

/*------------------------------------------------------------------*/

extern MSTATUS
QNX_timeGMT(TimeDate* td)
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

//#ifndef _KERNEL
#if 1

extern void *
QNX_malloc(ubyte4 size)
{
    return malloc(size);
}

extern void
QNX_free (void *ptr)
{
    free(ptr);
}

#endif


#endif /* __QNX_RTOS__ */

