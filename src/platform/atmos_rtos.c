/*
 * atmos_rtos.c
 *
 * ATMOS RTOS Abstraction Layer
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

#ifdef __ATMOS_RTOS__

#define MALLOC malloc
#define FREE   free

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include "atypes.h"
#include "config.h"

#ifdef QUANTUM_SUPPORT
#include <hs_semaphore.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "messages.h"
#include "netlib.h"
#include "timelib.h"
#include "kernel.h"
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>

#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#ifdef __ENABLE_DEBUG_RTOS_ATMOS__
extern void kprintf(const char*, ...);
#endif /* __ENABLE_DEBUG_RTOS_ATMOS__ */

/* Pull in Quantum OS code for mutex implementation -- NOT standard ATMOS code! */
#ifdef QUANTUM_SUPPORT
#define MAX_SEMA_NAME       40
#define SEMA_BASE_PATH      "//semaphore/mutexSemaId"

static sbyte4 gSemaMutexId = 0;
#endif


#if ((!defined(__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)) && (!defined(__DISABLE_DIGICERT_ATMOS_PORT_NOTICE__)))
#error Port not complete for non-async APIs
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
#ifdef QUANTUM_SUPPORT
    char    lSemaName[MAX_SEMA_NAME];
    char    lBuf[20];
    MSTATUS status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount); /* For numbering mutexes - not lock count */

    sprintf(lSemaName, SEMA_BASE_PATH);
    sprintf(lBuf, "%d", gSemaMutexId++);
    strcat(lSemaName, lBuf);

    if (kASEOK == as_SemaphoreNew(pMutex, lSemaName, "control=1"))
        status = OK;

    return status;
#else
    MOC_UNUSED(pMutex);
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    return OK;
#endif
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_mutexWait(RTOS_MUTEX mutex)
{
    MSTATUS status = OK;

#ifdef QUANTUM_SUPPORT
    if (kASEOK != as_SemaphoreWait(mutex))
        status = ERR_RTOS_MUTEX_WAIT;
#else
    /* not necessary for async apis */
   MOC_UNUSED(mutex);
#endif

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_mutexRelease(RTOS_MUTEX mutex)
{
    MSTATUS status = OK;

#ifdef QUANTUM_SUPPORT
    if (kASEOK != as_SemaphorePost(mutex))
        status = ERR_RTOS_MUTEX_RELEASE;
#else
    MOC_UNUSED(mutex);
#endif

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_mutexFree(RTOS_MUTEX *pMutexPtr)
{
#ifdef QUANTUM_SUPPORT
    MSTATUS status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == *pMutexPtr) || (NULL == pMutexPtr))
        goto exit;

    if (kASEOK == as_SemaphoreDelete(*pMutexPtr))
    {
        *pMutexPtr = NULL;
        status = OK;
    }

exit:
    return status;
#else
    MOC_UNUSED(pMutexPtr);

    return OK;
#endif
}


/*------------------------------------------------------------------*/

extern ubyte4
ATMOS_getUpTimeInMS(void)
{
    unsigned long dwmsec;
    struct timeval what_time_it_is;

    gettimeofday(&what_time_it_is, NULL);

    dwmsec = (what_time_it_is.tv_usec >> 10);
    dwmsec += (what_time_it_is.tv_sec << 10);

    return dwmsec;
}


/*------------------------------------------------------------------*/

extern ubyte4
ATMOS_deltaMS(const moctime_t* origin, moctime_t* current)
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
ATMOS_sleepMS(ubyte4 sleepTimeInMS)
{
    timer_ms_wait(sleepTimeInMS);
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    MSTATUS status = OK;
    MOC_UNUSED(threadType);
    MOC_UNUSED(pRetTid);

#ifdef __ENABLE_DEBUG_RTOS_ATMOS__
    kprintf("...in ATMOS_threadCreate...\n");
#endif

    if (NULL == thread_create((int)context, (THREAD_PROC)threadEntry, 10000))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "ATMOS_createThread: thread_create() failed.");
        status = ERR_RTOS_THREAD_CREATE;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern void
ATMOS_destroyThread(RTOS_THREAD tid)
{
    MOC_UNUSED(tid);

    /* Not needed with this OS */
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_timeGMT(TimeDate* td)
{
    time_t currentTime = time(0);
    struct tm*  pCurrentTime = gmtime(&currentTime);

    if (NULL == td)
        return ERR_NULL_POINTER;

    td->m_year   = (ubyte)(pCurrentTime->tm_year - 70);
    td->m_month  = (ubyte)pCurrentTime->tm_mon;
    td->m_day    = (ubyte)pCurrentTime->tm_mday;
    td->m_hour   = (ubyte)pCurrentTime->tm_hour;
    td->m_minute = (ubyte)pCurrentTime->tm_min;
    td->m_second = (ubyte)pCurrentTime->tm_sec;

    return OK;
}

#endif /* __ATMOS_RTOS__ */

