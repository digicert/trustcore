/*
 * psos_rtos.c
 *
 * pSOS RTOS Abstraction Layer
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

#ifdef __PSOS_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"

#include "../common/debug_console.h"

#include <psos.h>
#include <version.h>
#if VERSION >= 250
#include <signal.h>
#endif
#include <time.h>
#include <pna.h>

#define _REENTRANT

#ifndef SSH_THREAD_PRIORITY
#define SSH_THREAD_PRIORITY     (100)
#endif

#ifndef SSH_MAX_TASK_IDS
#define SSH_MAX_TASK_IDS        (100)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    CHAR    name[4];
    ULONG   mutex;
    MSTATUS status = ERR_RTOS_MUTEX_CREATE;

    if (SSL_CACHE_MUTEX == mutexType)
    {
        name[0] = 'S';
        name[1] = 'S';
        name[2] = 'L';
    }
    else if (HW_ACCEL_CHANNEL_MUTEX == mutexType)
    {
        name[0] = 'H';
        name[1] = 'W';
        name[2] = 'A';
    }
    else if (IPSEC_REASSEMBLY_MUTEX == mutexType)
    {
        name[0] = 'I';
        name[1] = 'P';
        name[2] = 'S';
    }
    else if (IKE_MT_MUTEX == mutexType)
    {
        name[0] = 'I';
        name[1] = 'K';
        name[2] = 'E';
    }
    else if (MCP_NW_MUTEX == mutexType)
    {
        name[0] = 'M';
        name[1] = 'C';
        name[2] = 'P';
    }
    else if (SSH_SERVER_MUTEX == mutexType)
    {
        name[0] = 'S';
        name[1] = 'S';
        name[2] = 'H';
    }
    else if (TACACS_CLIENT_MUTEX == mutexType)
    {
        name[0] = 'T';
        name[1] = 'A';
        name[2] = 'C';
    }
    else if (EAP_INSTANCE_MUTEX == mutexType)
    {
        name[0] = 'E';
        name[1] = 'I';
        name[2] = 'M';
    }
    else if (EAP_SESSION_MUTEX == mutexType)
    {
        name[0] = 'E';
        name[1] = 'S';
        name[2] = 'M';
    }
    else if (FIREWALL_MUTEX == mutexType)
    {
        name[0] = 'F';
        name[1] = 'W';
        name[2] = 'M';
    }
    else if (SRTP_CACHE_MUTEX == mutexType)
    {
        name[0] = 'S';
        name[1] = 'R';
        name[2] = 'T';
    }
    else if (HSM_MUTEX == mutexType)
    {
        name[0] = 'H';
        name[1] = 'S';
        name[2] = 'M';
    }
    else if (EC_COMB_MUTEX == mutexType)
    {
        name[0] = 'E';
        name[1] = 'C';
        name[2] = 'C';
    }
    else if (OCSP_CACHE_MUTEX == mutexType)
    {
        name[0] = 'O';
        name[1] = 'C';
        name[2] = 'M';
    }
    else
    {
        /* unknown mutex type, please notify Digicert */
        goto exit;
    }

    name[3] = '0' + mutexCount;

    if (SUCCESS == sm_create(name, 1, SM_LOCAL|SM_PRIOR, &mutex))
    {
        *pMutex = (RTOS_MUTEX)mutex;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_mutexWait(RTOS_MUTEX mutex)
{
    ULONG   mutexId = (ULONG)mutex;
    MSTATUS status = OK;

    if (SUCCESS != sm_p(mutexId, SM_WAIT, 0))
    {
        status = ERR_RTOS_MUTEX_WAIT;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_mutexRelease(RTOS_MUTEX mutex)
{
    ULONG   mutexId = (ULONG)mutex;
    MSTATUS status = OK;

    if (SUCCESS != sm_v(mutexId))
    {
        status = ERR_RTOS_MUTEX_RELEASE;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_mutexFree(RTOS_MUTEX* pMutex)
{
    ULONG   mutex;
    MSTATUS status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    mutex = (ULONG)(*pMutex);

    if (SUCCESS == sm_delete(mutex))
    {
        *pMutex = NULL;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte4
PSOS_getUpTimeInMS(void)
{
    return (SysGetTickTime() * TS_MSECS_PER_TICK);
}


/*------------------------------------------------------------------*/

extern ubyte4
PSOS_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4  retVal = 0;
    ubyte4  tickCount;

    tickCount = SysGetTickTime();

    if (origin)
    {
        retVal = TS_MSECS_PER_TICK * (tickCount - origin->u.time[0]);
    }

    if (current)
    {
        current->u.time[0] = tickCount;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
PSOS_sleepMS(ubyte4 sleepTimeInMS)
{
    /* CLOCKS_PER_SEC, the number of ticks per second */
    /* Order is important, prevent rounding errors */
    tm_wkafter(TS_MSECS2TICKS(sleepTimeInMS));
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_createThread(void(*threadEntry)(void*), void* context,
                  ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    int             i;
    unsigned long   tid;
    CHAR            name[TASK_NAME_SIZE+1];
    ULONG           taskArgs[TASK_ARGS_MAX];
    static int      uniqId = 0;
    MSTATUS         status = OK;

    for (i = 0; i < TASK_ARGS_MAX; i++)
        taskArgs[i] = 0;

    switch (threadType)
    {
        case ENTROPY_THREAD:
            break;
        case SSL_MAIN:
            break;
        case SSH_MAIN:
            break;
        case SSH_SESSION:
            break;
        case DEBUG_CONSOLE:
            break;
        case EAP_MAIN:
            break;
        default:
            status = ERR_RTOS_THREAD_CREATE;
            DEBUG_PRINTNL(DEBUG_PLATFORM, "PSOS_createThread: unknown thread type.");
            goto exit;
    }

    /* generate a unique task name for each task */
    uniqId++;
    if (uniqId >= SSH_MAX_TASK_IDS) /* 100 */
    {
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    snprintf(name, TASK_NAME_SIZE + 1, "%s%2.2d", "mo", uniqId);
    if (!(t_ident(name, 0, &tid)))
    {
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    /* spawn a task to handle the new connection */
    if (0 != t_create(name, TASK_PRIO_NORMAL, TASK_STACK_SUP,
                      TASK_STACK_USER, TASK_FLAGS_NORMAL, &tid))
    {
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    /* start the task */
    taskArgs[0] = (ULONG)context;
    if ((t_start(tid, OS_TASK_MODE, threadEntry, taskArgs)) != 0)
    {
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    /* return the task id to Digicert */
    *pRetTid = tid;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
PSOS_destroyThread(RTOS_THREAD tid)
{
    /* delete the PSOS task */
    if (t_delete(tid) != 0)
    {
        /* !!!! should log an event here */
    }
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_timeGMT(TimeDate* td)
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

#endif /* __PSOS_RTOS__ */

