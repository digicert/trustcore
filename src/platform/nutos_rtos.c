/*
 * nutos_rtos.c
 *
 * NutOS RTOS Abstraction Layer
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

#ifdef __NUTOS_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <cfg/os.h>
#ifdef NUTDEBUG
#include <sys/osdebug.h>
#endif

#include <time.h>
#include <stdio.h>
#include <io.h>

#include <cfg/arch.h>
#include <dev/board.h>

#include <sys/thread.h>
#include <sys/timer.h>
#include <sys/event.h>
#include <sys/heap.h>

#ifndef MOCANA_DEFAULT_NUTOS_STACK_SIZE
#define MOCANA_DEFAULT_NUTOS_STACK_SIZE       (4000)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    /* co-operative RTOS -- mutexes are not necessary */
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_mutexWait(RTOS_MUTEX mutex)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_mutexRelease(RTOS_MUTEX mutex)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_mutexFree(RTOS_MUTEX* pMutex)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern ubyte4
NUTOS_getUpTimeInMS(void)
{
    return NutGetMillis();
}


/*------------------------------------------------------------------*/

extern ubyte4
NUTOS_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4  time[2];
    ubyte4  retVal = 0;

    time[0] = NutGetSeconds();
    time[1] = NutGetMillis() % 1000;

    /* origin and current can point to the same struct */
    if (origin)
    {
        ubyte4  time_delt[2];

        time_delt[0] = time[0] - origin->u.time[0];
        time_delt[1] = time[1] - origin->u.time[1];

        while (1000 < time_delt[1])
        {
            time_delt[1] += 1000;   /* counter-intuitive: we are dealing with unsigned values */
            time_delt[0]--;
        }

        retVal  = (time_delt[0] * 1000) + time_delt[1];
    }

    if (current)
    {
        current->u.time[0] = time[0];
        current->u.time[1] = time[1];
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
NUTOS_sleepMS(ubyte4 sleepTimeInMS)
{
    NutSleep(sleepTimeInMS);
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    int     stackSize   = MOCANA_DEFAULT_NUTOS_STACK_SIZE;
    char*   threadName;
    MSTATUS status = OK;

    switch (threadType)
    {
        case ENTROPY_THREAD:
        {
#ifdef MOCANA_ENTROPY_NUTOS_TASK_NAME
            threadName = MOCANA_ENTROPY_NUTOS_TASK_NAME;
#else
            threadName = "mocEntropy";
#endif
#ifdef MOCANA_ENTROPY_NUTOS_STACK_SIZE
            stackSize  = MOCANA_ENTROPY_NUTOS_STACK_SIZE;
#endif
            break;
        }

        case SSL_MAIN:
        {
#ifdef MOCANA_SSL_NUTOS_TASK_NAME
            threadName = MOCANA_SSL_NUTOS_TASK_NAME;
#else
            threadName = "mocSslMn";
#endif
#ifdef MOCANA_SSL_NUTOS_STACK_SIZE
            stackSize  = MOCANA_SSL_NUTOS_STACK_SIZE;
#else
            stackSize  = 6000;
#endif
            break;
        }

        case SSH_MAIN:
        {
#ifdef MOCANA_SSH_MAIN_NUTOS_TASK_NAME
            threadName = MOCANA_SSH_MAIN_NUTOS_TASK_NAME;
#else
            threadName = "mocSshMn";
#endif
#ifdef MOCANA_SSH_NUTOS_STACK_SIZE
            stackSize  = MOCANA_SSH_NUTOS_STACK_SIZE;
#endif
            break;
        }

        case SSH_SESSION:
        {
#ifdef MOCANA_SSH_NUTOS_TASK_NAME
            threadName = MOCANA_SSH_NUTOS_TASK_NAME;
#else
            threadName = "mocSsh";
#endif
#ifdef MOCANA_SSH_NUTOS_STACK_SIZE
            stackSize  = MOCANA_SSH_NUTOS_STACK_SIZE;
#endif
            break;
        }
        case EAP_MAIN:
        {
#ifdef MOCANA_EAP_MAIN_NUTOS_TASK_NAME
            threadName = MOCANA_EAP_MAIN_NUTOS_TASK_NAME;
#else
            threadName = "mocEapMn";
#endif
#ifdef MOCANA_EAP_NUTOS_STACK_SIZE
            stackSize  = MOCANA_EAP_NUTOS_STACK_SIZE;
#endif
            break;
        }

        case DEBUG_CONSOLE:
        {
#ifdef MOCANA_DEBUG_CON_NUTOS_TASK_NAME
            threadName = MOCANA_DEBUG_CON_NUTOS_TASK_NAME;
#else
            threadName = "mocDbgCon";
#endif
#ifdef MOCANA_DEBUG_CON_NUTOS_STACK_SIZE
            stackSize  = MOCANA_DEBUG_CON_NUTOS_STACK_SIZE;
#endif
            break;
        }

        case IKE_MAIN:
        {
#ifdef MOCANA_IKE_NUTOS_TASK_NAME
            threadName = MOCANA_IKE_NUTOS_TASK_NAME;
#else
            threadName = "tMocIke";
#endif
#ifdef MOCANA_IKE_NUTOS_STACK_SIZE
            stackSize  = MOCANA_IKE_NUTOS_STACK_SIZE;
#else
            stackSize  = 6000;
#endif
            break;
        }

        default:
        {
            status = ERR_RTOS_THREAD_CREATE;
            DEBUG_PRINTNL(DEBUG_PLATFORM, "NUTOS_createThread: unknown thread type.");
            DBUG_PRINT(DEBUG_PLATFORM, ("Unknown threadtype: %d", threadType));
            goto exit;
        }
    }

    *pRetTid = NutThreadCreate(threadName,
                               (void(*)(void *))threadEntry,
                               context,
                               stackSize);

    if (0 == *pRetTid)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "NUTOS_createThread: taskSpawn() failed.");
        status = ERR_RTOS_THREAD_CREATE;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
NUTOS_destroyThread(RTOS_THREAD tid)
{
    /* no method of killing a thread */
    return;
}


/*------------------------------------------------------------------*/

extern sbyte4
NUTOS_currentThreadId()
{
    /* no support for thread ids */
    return 0;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_timeGMT(TimeDate* td)
{
    time_t  currentTime;
    tm      calendarTime;

    /* get the current time */
    time(&currentTime);

    /* translate current time to gmt calendar */
    gmtime_r(&currentTime, &calendarTime);

    if (NULL == td)
        return ERR_NULL_POINTER;

    td->m_year   = (ubyte)(calendarTime.tm_year - 70);
    td->m_month  = (ubyte)calendarTime.tm_mon + 1; /* 1..12 and gmtime_r returns 0.11 */
    td->m_day    = (ubyte)calendarTime.tm_mday;
    td->m_hour   = (ubyte)calendarTime.tm_hour;
    td->m_minute = (ubyte)calendarTime.tm_min;
    td->m_second = (ubyte)calendarTime.tm_sec;

    return OK;
}

#endif /* __NUTOS_RTOS__ */
