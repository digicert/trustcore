/*
 * quadros_rtos.c
 *
 * Quadros RTOS Abstraction Layer
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

#ifdef __QUADROS_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include "rtxcapi.h"
#include "kproject.h"
#include "kcounter.h"
#include <stdio.h>


/*------------------------------------------------------------------*/

typedef struct
{
    char    mutexName[24];
    SEMA    mutex;

} mutexDescr;


/*------------------------------------------------------------------*/

static TICKS    m_startTimeTicks;


/*------------------------------------------------------------------*/

extern MSTATUS
QUADROS_rtosInit(void)
{
    /* initialize start time for QUADROS_getUpTimeInMS */
    KS_GetElapsedCounterTicks(TIMEBASE, &m_startTimeTicks);

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
QUADROS_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
QUADROS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    mutexDescr* pNewMutexCtx = NULL;
    KSRC        result;
    MSTATUS     status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pNewMutexCtx = MALLOC(sizeof(mutexDescr))))
        goto exit;

    DIGI_MEMSET((ubyte *)pNewMutexCtx, 0x00, sizeof(mutexDescr));

    snprintf(pNewMutexCtx->mutexName, sizeof(pNewMutexCtx->mutexName), "mocana[0x%08x]", mutexType);

    if (RC_GOOD == (result = KS_OpenMutx(pNewMutexCtx->mutexName, &pNewMutexCtx->mutex)))
    {
        *pMutex = (RTOS_MUTEX)pNewMutexCtx;
        pNewMutexCtx = NULL;

        status = OK;
    }

exit:
    if (NULL != pNewMutexCtx)
        FREE(pNewMutexCtx);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
QUADROS_mutexWait(RTOS_MUTEX mutex)
{
    mutexDescr* pMutexCtx = (mutexDescr *)mutex;
    MSTATUS     status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pMutexCtx) && (RC_GOOD == KS_TestMutxW(pMutexCtx->mutex)))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
QUADROS_mutexRelease(RTOS_MUTEX mutex)
{
    mutexDescr* pMutexCtx = (mutexDescr *)mutex;
    MSTATUS     status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pMutexCtx) && (RC_GOOD == KS_ReleaseMutx(pMutexCtx->mutex)))
         status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
QUADROS_mutexFree(RTOS_MUTEX* pMutex)
{
    mutexDescr* pMutexCtx;
    MSTATUS     status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    pMutexCtx = (mutexDescr *)(*pMutex);

    if (RC_GOOD == KS_CloseMutx(pMutexCtx->mutex))
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
QUADROS_getUpTimeInMS(void)
{
    ubyte4  retVal;
    TICKS   originTicks;
    TICKS   deltaTicks;

    /* copy origin tick, since */
    originTicks = m_startTimeTicks;

    deltaTicks = KS_GetElapsedCounterTicks(TIMEBASE, &originTicks);

    retVal = deltaTicks * CLKTICK;

    return retVal;
}


/*------------------------------------------------------------------*/

extern ubyte4
QUADROS_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4  retVal = 0;
    ubyte4  tickCount;

    tickCount = tx_time_get();

    if (origin)
    {
        TICKS   originTicks;
        TICKS   deltaTicks;

        /* copy origin tick, since */
        originTicks = origin->u.time[0];

        deltaTicks = KS_GetElapsedCounterTicks(TIMEBASE, &originTicks);

        retVal = deltaTicks * CLKTICK;
    }

    if (current)
    {
        TICKS   currentTicks;

        KS_GetElapsedCounterTicks(TIMEBASE, &currentTicks);
        current->u.time[0] = currentTicks;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
QUADROS_sleepMS(ubyte4 sleepTimeInMS)
{
    KS_SleepTask(COUNTER1, (TICKS)sleepTimeInMS/CLKTICK);
}


/*------------------------------------------------------------------*/

extern MSTATUS
QUADROS_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    /* Quadros does not support dynamic thread generation */
    /* Threads are used by random number generator and example code */
    /* Example code will need to be refactored, any threads required should be added to static thread table  */

#if ((!defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)) && (!defined(__DISABLE_DIGICERT_QUADROS_PORT_ERRORS__)))
#error Must add definition __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ for Quadros RTCX operating system
#endif

#if 0
    switch (threadType)
    {
        case ENTROPY_THREAD:
            threadName = "MOCANA_ENTROPY_THREAD";
            break;
        case SSL_MAIN:
            threadName = "MOCANA_SSL_MAIN";
            break;
        case DEBUG_CONSOLE:
            threadName = "MOCANA_DEBUG_CONSOLE";
            break;
        case SSL_UPCALL_DAEMON:
            threadName = "MOCANA_SSL_UPCALL";
            break;
        case SSH_UPCALL_DAEMON:
            threadName = "MOCANA_SSH_UPCALL";
            break;
        case SSH_MAIN:
            threadName = "MOCANA_SSH_MAIN";
            break;
        case SSH_SESSION:
            threadName = "MOCANA_SSH_SESSION";
            break;
        case HTTP_THREAD:
            threadName = "MOCANA_HTTP";
            break;
        case IKE_MAIN:
            threadName = "MOCANA_IKE_MAIN";
            break;
        case DEBUG_THREAD:
            threadName = "MOCANA_DEBUG_THREAD";
            break;
        default:
            threadName = "MOCANA_THREAD";
            break;
    }
#endif

exit:
    return ERR_RTOS_THREAD_CREATE;
}


/*------------------------------------------------------------------*/

extern void
QUADROS_destroyThread(RTOS_THREAD tid)
{
    /* nothing to do, this code is not necessary on Quadros RTXC operating system */
    return;
}


/*------------------------------------------------------------------*/

extern MSTATUS
QUADROS_timeGMT(TimeDate *td)
{
    /* according to RTXC Kernel User�s Guide, Volume 1, page 71 */
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

#endif /* __QUADROS_RTOS__ */

