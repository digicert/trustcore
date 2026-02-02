/*
 * deos_rtos.c
 *
 * DDC-I DEOS RTOS Abstraction Layer
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

/**************************************************************************************************
 *
 * Notes on integration
 *
 * - DEOS_timeGMT is not implemented; the platform does not provide any API for date and time.
 *
 * - Memory partitioner (see mem_part.h) is used to implement MALLOC and FREE. Memory is allocated
 *   from a static memory pool. User can adjust the pool size (gStaticMemPool) or allocate it
 *   through other means by modifying DESO_rtosInit(). The following preprocessor should be defined
 *   when compiling Mocana code:
 *
 *   #define MALLOC DESO_malloc
 *   #define FREE   DEOS_free
 *
 * - DEOS_mutexCreate and DEOS_createThread use predefined templates for mutexes and threads;
 *   user can modify the functions to choose a template base on mutexType or threadType.
 *
 * - To use Mocana TCP or UDP wrappers, user should define the macros DEOS_TCP_* and DEOS_UDP_* in
 *   deos_tcp.c and deso_udp.c. Alternatively, user can setup transport at application level.
 *
 **************************************************************************************************/

#include "../common/moptions.h"

#ifdef __DEOS_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/mem_part.h"

#include <deos.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>

#ifndef DEOS_MUTEX_TEMPLATE
#define DEOS_MUTEX_TEMPLATE "defaultMutexTemplate"
#endif

#ifndef DEOS_THREAD_TEMPLATE
#define DEOS_THREAD_TEMPLATE "defaultThreadTemplate"
#endif

static memPartDescr* gMemPartition;
static void* gMemPartBaseAddr;

static char gStaticMemPool[800000];


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_rtosInit(void)
{
    MSTATUS status;

    /* may need a proper way to allocate initial memory block */
    /* use static buffer for now */
    gMemPartBaseAddr = gStaticMemPool;

    if (OK > (status = MEM_PART_createPartition(&gMemPartition,
                            gMemPartBaseAddr, sizeof(gStaticMemPool))))
    {
        goto exit;
    }

exit:
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_rtosShutdown(void)
{
    MSTATUS status;

    if (OK > (status = MEM_PART_freePartition(&gMemPartition)))
        goto exit;

exit:
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
	mutex_handle_t  mutexHandle;
	mutexStatus     ret;
    MSTATUS         status = OK;

    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    ret = createMutex( "", DEOS_MUTEX_TEMPLATE, &mutexHandle);

    if (mutexSuccess != ret)
    {
        status = ERR_RTOS_MUTEX_CREATE;
        goto exit;
    }

    *pMutex = (RTOS_MUTEX)mutexHandle;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_mutexWait(RTOS_MUTEX mutex)
{
    mutex_handle_t  mutexHandle = (mutex_handle_t)mutex;
    MSTATUS         status = ERR_RTOS_MUTEX_WAIT;
    mutexStatus     ret;
    
    if (mutexHandle)
    {
        ret = lockMutex(mutexHandle);
        
        if (mutexSuccess == ret)
            status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_mutexRelease(RTOS_MUTEX mutex)
{
    mutex_handle_t  mutexHandle = (mutex_handle_t)mutex;
    MSTATUS         status = ERR_RTOS_MUTEX_RELEASE;
    mutexStatus     ret;

    if (mutexHandle)
    {
        ret = unlockMutex(mutexHandle);

        if (mutexSuccess == ret)
            status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_mutexFree(RTOS_MUTEX* pMutex)
{
    mutex_handle_t  mutexHandle;
    mutexStatus     ret;
    MSTATUS         status = OK;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    mutexHandle = (mutex_handle_t)(*pMutex);

    if (mutexSuccess != (ret = deleteMutex(mutexHandle)))
    {
        status = ERR_RTOS_MUTEX_FREE;
        goto exit;
    }

    *pMutex = NULL;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte4
DEOS_getUpTimeInMS(void)
{
    return (ubyte4)(*(systemTickPointer())) * systemTickInMicroseconds();
}


/*------------------------------------------------------------------*/

extern ubyte4
DEOS_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4 retVal = 0;
    ubyte4 deltaTicks = 0;
    ubyte4 tickCount;

    tickCount = (ubyte4)(*(systemTickPointer()));

    if (origin)
    {
        deltaTicks = (tickCount - origin->u.time[0]);
        retVal = deltaTicks * systemTickInMicroseconds();
    }

    if (current)
    {
        current->u.time[0] = tickCount;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern ubyte4
DEOS_deltaConstMS(const moctime_t* origin, const moctime_t* current)
{
    ubyte4 deltaTicks = current->u.time[0] - origin->u.time[0];

    return deltaTicks * systemTickInMicroseconds();
}


/*------------------------------------------------------------------*/

extern void
DEOS_sleepMS(ubyte4 sleepTimeInMS)
{
    ubyte4 ticksStart = *(systemTickPointer());
    ubyte4 rate = systemTickInMicroseconds();

    while(((*(systemTickPointer())-ticksStart)*rate/1000) < sleepTimeInMS)
    {
        waitUntilNextPeriod();
    }
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
	thread_handle_t   tid;
    threadStatus      ret;
    MSTATUS           status  = OK;

    MOC_UNUSED(threadType);

    ret = createThread( "", DEOS_THREAD_TEMPLATE,
                       (UserFun1)threadEntry, (DWORD)context, &tid);

    if (ret != threadSuccess)
    {
    	DEBUG_ERROR(DEBUG_PLATFORM, "DEOS_createThread: pthread_create error ", ret);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    *pRetTid = tid;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
DEOS_destroyThread(RTOS_THREAD tid)
{
	deleteThread( tid); /* mark the thread for deletion */
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_timeGMT(TimeDate* td)
{
    return ERR_RTOS_GMT_TIME_NOT_AVAILABLE;
}


/*------------------------------------------------------------------*/

extern void*
DEOS_malloc(DWORD sizeInBytes)
{
    void* addr = NULL;

    if (sizeInBytes <= 0)
        return NULL;

    if (OK > MEM_PART_alloc(gMemPartition, (ubyte4)sizeInBytes, &addr))
        return NULL;

    return addr;
}


/*------------------------------------------------------------------*/

extern void
DEOS_free(void* addr)
{
    MEM_PART_free(gMemPartition, (void **)(&addr));
}

#endif /* __DEOS_RTOS__ */
