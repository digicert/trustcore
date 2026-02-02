/*
 * nucleus_rtos.c
 *
 * Nucleus RTOS Abstraction Layer
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

#ifdef __NUCLEUS_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <nucleus.h>

#define NANOS 1000000000
#define _REENTRANT

#ifndef MOCANA_THREAD_PRIO
#define MOCANA_THREAD_PRIO 10
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    NU_SEMAPHORE*   pNucMutex;
    MSTATUS         status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pNucMutex = MALLOC(sizeof(NU_SEMAPHORE))))
        goto exit;

    DIGI_MEMSET((ubyte *)pNucMutex, 0x00, sizeof(NU_SEMAPHORE));

    if (NU_SUCCESS == NU_Create_Semaphore(pNucMutex, "mocSem", 1, NU_FIFO))
    {
        *pMutex = (RTOS_MUTEX)pNucMutex;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_mutexWait(RTOS_MUTEX mutex)
{
    NU_SEMAPHORE*   pNucMutex = (NU_SEMAPHORE *)mutex;
    MSTATUS         status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pNucMutex) &&
        (NU_SUCCESS == NU_Obtain_Semaphore(pNucMutex, NU_SUSPEND))))
    {
        status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_mutexRelease(RTOS_MUTEX mutex)
{
    NU_SEMAPHORE*   pNucMutex = (NU_SEMAPHORE *)mutex;
    MSTATUS         status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pNucMutex) &&
        (NU_SUCCESS == NU_Release_Semaphore(pNucMutex)))
    {
        status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_mutexFree(RTOS_MUTEX* pMutex)
{
    NU_SEMAPHORE*   pNucMutex;
    MSTATUS         status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    pNucMutex = (NU_SEMAPHORE *)(*pMutex);

    if (NU_SUCCESS == NU_Delete_Semaphore(pNucMutex))
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
NUCLEUS_getUpTimeInMS(void)
{
    return (100 * NU_Retrieve_Clock());
}


/*------------------------------------------------------------------*/

extern ubyte4
NUCLEUS_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4  retVal = 0;
    ubyte4  clockCount;

    clockCount = NU_Retrieve_Clock();

    if (origin)
    {
        retVal = 100 * (clockCount - origin->u.time[0]);
    }

    if (current)
    {
        current->u.time[0] = clockCount;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
NUCLEUS_sleepMS(ubyte4 sleepTimeInMS)
{
    ubyte4 sleepTime = sleepTimeInMS / 100;

    NU_Sleep(sleepTime);
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_createThread(void (*threadEntry)(void*), void* context,
                     ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    int         i;
    NU_TASK     tid;
    int         ret;
    MSTATUS     status  = OK;

    /* threadType is ignored for this platform, use default values */
    ret = NU_Create_Task(&tid, threadEntry,
                         context, 0, stackBasePtr,
                         stackSize, MOCANA_THREAD_PRIO, 0,
                         NU_PREEMPT, NU_START);

    if (NU_SUCCESS != ret)
        return ERR_RTOS_THREAD_CREATE;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
NUCLEUS_destroyThread(RTOS_THREAD tid)
{
    /* Not needed with this OS */
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_timeGMT(TimeDate* td)
{
    /* Nucleus doesn't support GMT */
    return ERR_RTOS_GMT_TIME_NOT_AVAILABLE;
}

#endif /* __NUCLEUS_RTOS__ */
