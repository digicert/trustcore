/*
 * supertask_rtos.c
 *
 * SuperTask! RTOS Abstraction Layer
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

#ifdef __SUPERTASK_RTOS__


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
SUPERTASK_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SUPERTASK_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SUPERTASK_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    return ERR_RTOS_MUTEX_CREATE;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SUPERTASK_mutexWait(RTOS_MUTEX mutex)
{
    return ERR_RTOS_MUTEX_WAIT;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SUPERTASK_mutexRelease(RTOS_MUTEX mutex)
{
    return ERR_RTOS_MUTEX_RELEASE;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SUPERTASK_mutexFree(RTOS_MUTEX* pMutex)
{
    return ERR_RTOS_MUTEX_FREE;
}


/*------------------------------------------------------------------*/

extern ubyte4
SUPERTASK_getUpTimeInMS(void)
{
    return (ubyte4)ussTimeMS();
}


/*------------------------------------------------------------------*/

extern ubyte4
SUPERTASK_deltaMS(const moctime_t* origin, moctime_t* current)
{
    DWORD   time;
    ubyte4  retVal = 0;

    time = ussTimeMS();

    /* origin and current can point to the same struct */
    if (origin)
    {
        retVal = time - origin->u.time[0]);
    }

    if (current)
    {
        current->u.time[0] = time;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
SUPERTASK_sleepMS(ubyte4 sleepTimeInMS)
{
    delay_until(0, curTick + uss_mSecToTicks(sleepTimeInMS));
}


/*------------------------------------------------------------------*/

extern MSTATUS
SUPERTASK_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetSlot)
{
    int     slot;
    MSTATUS status  = OK;

    /* threadType is ignored for this platform, use default values */
    if (0 > (slot = runtsk(SUPERTASK_PRIORITY, (void(*))threadEntry, SUPERTASK_STACKSIZE, context))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "SUPERTASK_createThread: create_task failed, threadType = ", threadType);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    *pRetSlot = (RTOS_THREAD)slot;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
SUPERTASK_destroyThread(RTOS_THREAD slot)
{
    klltsk((int)slot);
}


/*------------------------------------------------------------------*/

extern sbyte4
SUPERTASK_currentThreadId(void)
{
    return (sbyte4)slttsk(NULLFP);
}


/*------------------------------------------------------------------*/

extern MSTATUS
SUPERTASK_timeGMT(TimeDate* td)
{
    return ERR_RTOS_GMT_TIME_NOT_AVAILABLE;
}

#endif /* __SUPERTASK_RTOS__ */

