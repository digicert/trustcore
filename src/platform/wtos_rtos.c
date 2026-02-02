/*
 * wtos_rtos.c
 *
 * WTOS RTOS Abstraction Layer
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../common/moptions.h"

#ifdef __WTOS_RTOS__


#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#ifdef NANO
#include <sys/times.h>
#endif
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <sys/param.h>
#include <sys/proc.h>

#define NANOS 1000000000
/* #define _REENTRANT */



/*------------------------------------------------------------------*/

extern MSTATUS
WTOS_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WTOS_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WTOS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    CRITICAL_SECTION* pPthreadMutex;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pPthreadMutex = MALLOC(sizeof(CRITICAL_SECTION))))
        goto exit;

    InitializeCriticalSection(pPthreadMutex);
    *pMutex = (RTOS_MUTEX *)pPthreadMutex;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WTOS_mutexWait(RTOS_MUTEX mutex)
{
    CRITICAL_SECTION* pPthreadMutex = (CRITICAL_SECTION *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (!(0 > EnterCriticalSection(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WTOS_mutexRelease(RTOS_MUTEX mutex)
{
    CRITICAL_SECTION* pPthreadMutex = (CRITICAL_SECTION *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadMutex)) {
        LeaveCriticalSection(pPthreadMutex);
        status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WTOS_mutexFree(RTOS_MUTEX* pMutex)
{
    CRITICAL_SECTION* pPthreadMutex;
    MSTATUS          status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    pPthreadMutex = (CRITICAL_SECTION *)(*pMutex);

    DeleteCriticalSection(pPthreadMutex);
    FREE(*pMutex);
    *pMutex = NULL;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte4
WTOS_getUpTimeInMS(void)
{
    ubyte4     ms;
    extern time_t lbolt;

    ms = lbolt * MS_PER_TICK;

    return ms;
}


/*------------------------------------------------------------------*/

extern ubyte4
WTOS_deltaMS(const moctime_t* origin, moctime_t* current)
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
WTOS_sleepMS(ubyte4 sleepTimeInMS)
{
    ubyte4 sleepTimeInTenMS;

    sleepTimeInTenMS = sleepTimeInMS / 10;

    delay(sleepTimeInTenMS);
}


/*------------------------------------------------------------------*/

void thread_add_arg(p, arg)
    struct  proc    *p;
{
    p->p_jmpbuf[1] = arg;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WTOS_createThread(void (*threadEntry)(void *), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    proc_t      *tid;
    int         ret;
    MSTATUS     status  = OK;

    /* FIXME :: need to implment
                Get Thread Type from threadType */

    if (tid = newproc(threadEntry, "mocana_threadType", 0x200)) {
        thread_add_arg(tid, context);
        qswtch();
    } else {
        DEBUG_ERROR(DEBUG_PLATFORM, "WTOS_createThread: pthread_create error ", -1);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    *pRetTid = *((sbyte4 *)tid);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
WTOS_destroyThread(RTOS_THREAD tid)
{
    /* FIXME :: No need in WTOS? */
}


/*------------------------------------------------------------------*/

extern sbyte4
WTOS_currentThreadId()
{
    return((sbyte4) curproc);
}


/*------------------------------------------------------------------*/

extern MSTATUS
WTOS_timeGMT(TimeDate* td)
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

#endif /* __WTOS_RTOS__ */
