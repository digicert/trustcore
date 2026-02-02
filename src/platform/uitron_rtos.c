/*
 * uitron_rtos.c
 *
 * uITRON (Spec 4.0) RTOS Abstraction Layer
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

#ifdef __UITRON_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <itron.h>
#include <kernel.h>


/*------------------------------------------------------------------*/

typedef struct threadContext
{
    void* pContext;
    void(*threadEntry)(void*);

} threadContext;


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    pthread_mutex_t* pPthreadMutex;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    /*!-!-!-! this needs work here */

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
UITRON_mutexWait(RTOS_MUTEX mutex)
{
    ID      threadMutex = (ID)mutex;
    MSTATUS status      = ERR_RTOS_MUTEX_WAIT;

    if (E_OK == wai_sem(threadMutex))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_mutexRelease(RTOS_MUTEX mutex)
{
    ID      threadMutex = (ID)mutex;
    MSTATUS status      = ERR_RTOS_MUTEX_RELEASE;

    if (E_OK == sig_sem(threadMutex))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_mutexFree(RTOS_MUTEX* pMutex)
{
    /*!-!-!-! can't delete mutexes */
    return OK;
}


/*------------------------------------------------------------------*/

extern ubyte4
UITRON_getUpTimeInMS(void)
{
    SYSTIM  curTime;

    /* Nice: page 61 of uITRON spec indicates SYSTIM is in milliseconds */
    get_tim(&curTime);

    return curTime;
}


/*------------------------------------------------------------------*/

extern ubyte4
UITRON_deltaMS(const moctime_t* origin, moctime_t* current)
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
UITRON_sleepMS(ubyte4 sleepTimeInMS)
{
    /* Nice: page 61 of uITRON spec indicates RELTIM is in milliseconds */
    dly_tsk((RELTIM)sleepTimeInMS);
}


/*------------------------------------------------------------------*/

static void
UITRON_threadEntry(VP_INT exintf)
{
    threadContext*  pThreadContext = (threadContext *)exintf;
    void*           pContext;
    void(*threadEntry)(void*);

    if (NULL != pThreadContext)
    {
        pContext    = pThreadContext->pContext;
        threadEntry = pThreadContext->threadEntry;

        /* release memory associated thread context before spawning the thread to minimize heap usage */
        FREE(pThreadContext);

        if (NULL != pThreadContext->threadEntry)
        {
            /* run the thread code */
            threadEntry(pContext);
        }
    }

    ext_tsk();
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    pthread_t   tid;
    int         ret;
    MSTATUS     status  = OK;

    /* threadType is ignored for this platform, use default values */

    if (0 > (ret = pthread_create(&tid, NULL, (void *(*)(void *))threadEntry, context)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "UITRON_createThread: pthread_create error ", ret);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    *pRetTid = tid;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
UITRON_destroyThread(RTOS_THREAD tid)
{
    ter_tsk((ID)tid); /* mark the thread for deletion */
}


/*------------------------------------------------------------------*/

extern sbyte4
UITRON_currentThreadId()
{
    ID  curTid;

    get_tid(&curTid);

    return (sbyte4)curTid;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_timeGMT(TimeDate* td)
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

#endif /* __UITRON_RTOS__ */
