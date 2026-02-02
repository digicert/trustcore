/*
 * integrity_rtos.c
 *
 * GHS Integrity RTOS Abstraction Layer
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

#ifdef __INTEGRITY_RTOS__


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
#ifndef __INTEGRITY_POSIXLIB__

/*! global var holding the basis time used for uptime computation */
static time_t s_basistime;

#endif


/*------------------------------------------------------------------*/

extern MSTATUS
INTEGRITY_rtosInit(void)
{
#ifndef __INTEGRITY_POSIXLIB__
    s_basistime = time(NULL);
#endif

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
INTEGRITY_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
INTEGRITY_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    MSTATUS status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (!CreateBinarySemaphore((Semaphore *)pMutex))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
INTEGRITY_mutexWait(RTOS_MUTEX mutex)
{
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if (!WaitForSemaphore(mutex))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
INTEGRITY_mutexRelease(RTOS_MUTEX mutex)
{
    MSTATUS status  = ERR_RTOS_MUTEX_RELEASE;

    if (!ReleaseSemaphore(mutex))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
INTEGRITY_mutexFree(RTOS_MUTEX* pMutex)
{
    MSTATUS status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    if (!CloseSemaphore(*pMutex))
    {
        *pMutex = NULL;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte4
INTEGRITY_getUpTimeInMS(void)
{
#ifdef __INTEGRITY_POSIXLIB__
    struct tms tstruct;
    clock_t    uptime;
    ubyte4     ms;

    uptime=times(&tstruct);

    if (uptime==-1)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "ERROR: Could not get time values.");
        return (ubyte4)-1;
    }

    ms = (uptime*1000.0)/sysconf(_SC_CLK_TCK);

    return ms;
#else
    time_t curtime;
    double diff;

    curtime = time(NULL);
    diff = difftime(curtime, s_basistime);
    if (diff < 0)
    {
        /* time wrapped around... error */
        return (ubyte4)-1;
    }

    /* convert difference in time (s) into (ms) */
    return (ubyte4) (diff*1000.);
#endif

}


/*------------------------------------------------------------------*/

extern ubyte4
INTEGRITY_deltaMS(const moctime_t* origin, moctime_t* current)
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
INTEGRITY_sleepMS(ubyte4 sleepTimeInMS)
{
#ifdef __INTEGRITY_POSIXLIB__
    struct timespec nanopause;

    nanopause.tv_sec = sleepTimeInMS / 1000;
    nanopause.tv_nsec = 1000000 * (sleepTimeInMS % 1000);

    nanosleep(&nanopause,0);
#else
    usleep( sleepTimeInMS * 1000 );
#endif
}


#ifdef __INTEGRITY_POSIXLIB__

/*------------------------------------------------------------------*/

/* eliminate warning about 'ret' never used */
#pragma ghs nowarning 550

extern MSTATUS
INTEGRITY_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    pthread_t   tid;
    int         ret;
    MSTATUS     status  = OK;

    /* threadType is ignored for this platform, use default values */

    if (0 > (ret = pthread_create(&tid, NULL, (void *(*)(void *))threadEntry, context)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "INTEGRITY_createThread: pthread_create error ", ret);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    *pRetTid = tid;

exit:
    return status;
}

#pragma ghs endnowarning

/*------------------------------------------------------------------*/

extern void
INTEGRITY_destroyThread(RTOS_THREAD tid)
{
    pthread_detach((pthread_t) tid); /* mark the thread for deletion */
}


/*------------------------------------------------------------------*/

extern sbyte4
INTEGRITY_currentThreadId()
{
    return (sbyte4) pthread_self();
}

#else

typedef struct
{
    void (*threadEntry)(void*);
    void* context;
} ThreadData_t;


/* -------------------------------------------------------------------- */
static void
_thread_wrapper()
{
    ThreadData_t *data, ourData;

    GetTaskIdentification(CurrentTask(), (Address*)&data);
    ourData = *data;    /* copy our data */

    /* get rid of the passed data now, as our task maybe killed
    ** and we don't want to leak the memory
    */
    free(data);

    /* transfer to the thread function */
    ourData.threadEntry( ourData.context );

    Exit(0);
}
/* -------------------------------------------------------------------- */

extern MSTATUS
INTEGRITY_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    Task         theTask;
    MSTATUS      status  = OK;
    Error        err;
    int          stacksize;
    ThreadData_t *data;

    /* based on the thread type, choose a better stack size */
    if (threadType == ENTROPY_THREAD)
        stacksize = 1024;
    else
        stacksize = 4096;

    err = CommonCreateTask(127, (Address)_thread_wrapper, stacksize, "", &theTask);
    if (err != Success)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "INTEGRITY_createThread: CommonCreateTask error ", err);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    /* create data on the heap, the task wrapper will free */
    data = malloc(sizeof(*data));
    data->threadEntry = threadEntry;
    data->context = context;
    SetTaskIdentification(theTask, (Address)data);

    RunTask(theTask);

    *pRetTid = theTask;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
INTEGRITY_destroyThread(RTOS_THREAD tid)
{
    CommonCloseTask( (Task)tid );
}


/*------------------------------------------------------------------*/

extern sbyte4
INTEGRITY_currentThreadId()
{
    return (sbyte4) CurrentTask();
}


#endif   /* __INTEGRITY_POSIXLIB__ */


/*------------------------------------------------------------------*/

extern MSTATUS
INTEGRITY_timeGMT(TimeDate* td)
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

#endif /* __INTEGRITY_RTOS__ */
