/*
 * smx_rtos.c
 *
 * SMX RTOS Abstraction Layer
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

#ifdef __SMX_RTOS__


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
#include <asm/param.h>


/*------------------------------------------------------------------*/

extern MSTATUS
SMX_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SMX_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SMX_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    MSTATUS status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (*pMutex = (RTOS_MUTEX)create_mutex(1, HI)))
        goto exit;

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SMX_mutexWait(RTOS_MUTEX mutex)
{
    MSTATUS status = ERR_RTOS_MUTEX_WAIT;

    if (FALSE != get_mutex((MUCB_PTR)mutex, INF))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SMX_mutexRelease(RTOS_MUTEX mutex)
{
    MSTATUS status  = ERR_RTOS_MUTEX_RELEASE;

    if (FALSE != rel_mutex((MUCB_PTR)mutex))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SMX_mutexFree(RTOS_MUTEX* pMutex)
{
    MSTATUS status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    if (FALSE != delete_mutex(&((MUCB_PTR)pMutex)))
    {
        *pMutex = NULL;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte4
SMX_getUpTimeInMS(void)
{
    return (ubyte4)SMX_TICKS_TO_MSEC(get_etime());
}


/*------------------------------------------------------------------*/

extern ubyte4
SMX_deltaMS(const moctime_t* origin, moctime_t* current)
{
    DWORD   time;
    ubyte4  retVal = 0;

    time = get_etime();

    /* origin and current can point to the same struct */
    if (origin)
    {
        retVal = SMX_TICKS_TO_MSEC((ubyte4)time - origin->u.time[0]);
    }

    if (current)
    {
        current->u.time[0] = time;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
SMX_sleepMS(ubyte4 sleepTimeInMS)
{
    suspend(ct, SMX_MSEC_TO_TICKS(sleepTimeInMS));
}


/*------------------------------------------------------------------*/

extern MSTATUS
SMX_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, void* pRetTid)
{
    TCB_PTR tid;
    int     ret;
    MSTATUS status  = OK;

    /* threadType is ignored for this platform, use default values */

    if (NULL = (tid = create_task((void *(*)(void *))threadEntry, 0, 4000)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "SMX_createThread: create_task failed, threadType = ", threadType);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    start_par(tid, context);

    *pRetTid = tid;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
SMX_destroyThread(RTOS_THREAD tid)
{
    delete_task(&((TCB_PTR)tid));
}


/*------------------------------------------------------------------*/

extern sbyte4
SMX_currentThreadId(void)
{
    return (sbyte4)ct;  /* ct (current task) - an SMX global var */
}


/*------------------------------------------------------------------*/

extern MSTATUS
SMX_timeGMT(TimeDate* td)
{
    return ERR_RTOS_GMT_TIME_NOT_AVAILABLE;
}

#endif /* __SMX_RTOS__ */
