/*
 * mqx_rtos.c
 *
 * MQX RTOS Abstraction Layer
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

#ifdef __MQX_RTOS__

#include <mqx.h>
#include <mutex.h>
#include <rtcs.h>

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

typedef struct
{
    TASK_TEMPLATE_STRUCT    taskTemplate;       /* thread descriptor */
    _task_id                tid;
    intBoolean              inUse;              /* table entry used */
    char                    taskName[20];

} threadContext;


#define MAX_NUM_MQX_THREADS      10

static MUTEX_STRUCT     mThreadCreationMutex;
static threadContext    mp_threadDescriptor[MAX_NUM_MQX_THREADS];


/*------------------------------------------------------------------*/

extern MSTATUS
MQX_rtosInit(void)
{
    _mqx_uint   err;
    int         index;
    MSTATUS     status = OK;

    /* initialize thread context handler */
    for (index = 0; index < MAX_NUM_MQX_THREADS; index++)
    {
        mp_threadDescriptor[index].inUse = FALSE;
    }

    /* create thread context mutex guard */
    err = _mutex_init(&mThreadCreationMutex, NULL);

    if (MQX_EOK != err)
        status = ERR_RTOS_MUTEX_CREATE;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MQX_rtosShutdown(void)
{
    MSTATUS status = OK;

    if (MQX_EOK != _mutex_destroy(&mThreadCreationMutex))
        status = ERR_RTOS_MUTEX_FREE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MQX_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    MUTEX_STRUCT*   pMqxMutex;
    MSTATUS         status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pMqxMutex = MALLOC(sizeof(MUTEX_STRUCT))))
        goto exit;

    DIGI_MEMSET((ubyte *)pMqxMutex, 0x00, sizeof(MUTEX_STRUCT));

    if (MQX_EOK == _mutex_init(pMqxMutex, NULL))
    {
        *pMutex = (RTOS_MUTEX)pMqxMutex;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MQX_mutexWait(RTOS_MUTEX mutex)
{
    MUTEX_STRUCT*   pMqxMutex = (MUTEX_STRUCT *)mutex;
    MSTATUS         status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pMqxMutex) && (MQX_EOK == _mutex_lock(pMqxMutex)))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MQX_mutexRelease(RTOS_MUTEX mutex)
{
    MUTEX_STRUCT*   pMqxMutex = (MUTEX_STRUCT *)mutex;
    MSTATUS         status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pMqxMutex) && (MQX_EOK == _mutex_unlock(pMqxMutex)))
         status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MQX_mutexFree(RTOS_MUTEX* pMutex)
{
    MUTEX_STRUCT*   pMqxMutex;
    MSTATUS         status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    pMqxMutex = (MUTEX_STRUCT *)(*pMutex);

    if (MQX_EOK == _mutex_destroy(pMqxMutex))
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
MQX_getUpTimeInMS(void)
{
    TIME_STRUCT currentTime = { 0 };

    _time_get(&currentTime);

    return (ubyte4)(currentTime.SECONDS * 1000);
}


/*------------------------------------------------------------------*/

extern ubyte4
MQX_deltaMS(const moctime_t* origin, moctime_t* current)
{
    TIME_STRUCT currentTime = { 0 };
    ubyte4      retVal = 0;

    _time_get(&currentTime);

    /* origin and current can point to the same struct */
    if (origin)
    {
        retVal = ((currentTime.SECONDS - origin->u.time[0]) * 1000) + (currentTime.MILLISECONDS - origin->u.time[1]);
    }

    if (current)
    {
        current->u.time[0] = currentTime.SECONDS;
        current->u.time[1] = currentTime.MILLISECONDS;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
MQX_sleepMS(ubyte4 sleepTimeInMS)
{
    _time_delay((uint_32)sleepTimeInMS);
}


/*------------------------------------------------------------------*/

extern MSTATUS
MQX_createThread(void(*threadEntry)(void*), void* context,
                     ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    static int              uniqId;
    TASK_TEMPLATE_STRUCT*   pTaskTemplate  = NULL;
    char*                   pThreadName;
    _mem_size               stackSize      = 4000;
    _mqx_uint               priority       = 7;
    _mqx_uint               time_slice     = 1000;
    sbyte4                  index          = -1;
    MSTATUS                 status         = OK;

    if ((NULL == threadEntry) || (NULL == pRetTid))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* set return tid to invalid value */
    *pRetTid = (void *)-1;

    /* set thread name */
    switch (threadType)
    {
        case ENTROPY_THREAD:
            pThreadName = "mocEntropy";
            break;
        case SSL_MAIN:
            pThreadName = "mocSslMn";
            stackSize   = 6000;
            break;
        case SSH_MAIN:
            pThreadName = "mocSshMn";
            break;
        case SSH_SESSION:
            pThreadName = "mocSsh";
            break;
        case DEBUG_CONSOLE:
            pThreadName = "mocDbgCon";
            break;
        case SSL_SERVER_SESSION:
            pThreadName = "mocSslSrv";
            break;
        default:
            pThreadName = "mocGeneric";
            DEBUG_PRINTNL(DEBUG_PLATFORM, (signed char *)"MQX_createThread: Defaulting to Generic thread type.");
    }

    /* min stack size guard */
    if (5000 > stackSize)
        stackSize = 5000;

    /* mutex protect mp_threadDescriptor */
    if (MQX_EOK != _mutex_lock(&mThreadCreationMutex))
    {
        status = ERR_RTOS_MUTEX_WAIT;
        goto exit;
    }

    /* access thread table */
    for (index = (MAX_NUM_MQX_THREADS-1); 0 <= index; index--)
    {
        if (FALSE == mp_threadDescriptor[index].inUse)
        {
            mp_threadDescriptor[index].inUse = TRUE;
            pTaskTemplate = &(mp_threadDescriptor[index].taskTemplate);

            uniqId++;
            sprintf(mp_threadDescriptor[index].taskName, "%s%d", pThreadName, uniqId);
            break;
        }
    }

    /* mutex unprotect mp_threadDescriptor */
    if (MQX_EOK != _mutex_unlock(&mThreadCreationMutex))
    {
        status = ERR_RTOS_MUTEX_RELEASE;
        goto exit;
    }

    /* table full */
    if (0 > index)
    {
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    DIGI_MEMSET((unsigned char *)pTaskTemplate, 0x00, sizeof(TASK_TEMPLATE_STRUCT));

    pTaskTemplate->TASK_ADDRESS       = (void (*)(unsigned long))threadEntry;
    pTaskTemplate->TASK_STACKSIZE     = stackSize;
    pTaskTemplate->TASK_PRIORITY      = priority;
    pTaskTemplate->TASK_NAME          = mp_threadDescriptor[index].taskName;
    pTaskTemplate->TASK_ATTRIBUTES    = MQX_AUTO_START_TASK;
    pTaskTemplate->CREATION_PARAMETER = (uint_32)context;
    pTaskTemplate->DEFAULT_TIME_SLICE = time_slice;

    /* spawn the thread */
    mp_threadDescriptor[index].tid = (sbyte4)_task_create(0, 0, (uint_32)pTaskTemplate);

    if (MQX_NULL_TASK_ID == mp_threadDescriptor[index].tid)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        printf("MQX_createThread: _task_create() failed.\n");
#endif
        status = _task_get_error();
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    /* set return tid, used by MQX_destroyThread() */
    *pRetTid = (void *)index;

    /* thread spawned successfully, don't release resources */
    index = -1;

exit:
    if (0 <= index)
        mp_threadDescriptor[index].inUse = FALSE;

    return status;
}


/*------------------------------------------------------------------*/

extern void
MQX_destroyThread(RTOS_THREAD tid)
{
    int index = (int) tid;
    if (((0 <= index) && (MAX_NUM_MQX_THREADS > index)) &&
        (TRUE == mp_threadDescriptor[index].inUse))
    {
        /* terminate thread */
        _task_destroy(mp_threadDescriptor[index].tid);
        mp_threadDescriptor[index].inUse = FALSE;
    }
}


/*------------------------------------------------------------------*/

extern MSTATUS
MQX_timeGMT(TimeDate* td)
{
    DATE_STRUCT date;
    TIME_STRUCT time;

    if (0 == td)
    {
        return ERR_NULL_POINTER;
    }

    _time_get(&time);
    _time_to_date(&time, &date);

    if (2005 > date.YEAR)
        date.YEAR = 2005;

    td->m_year   = (ubyte)(date.YEAR - 1970);
    td->m_month  = (ubyte)date.MONTH;
    td->m_day    = (ubyte)date.DAY;
    td->m_hour   = (ubyte)date.HOUR;
    td->m_minute = (ubyte)date.MINUTE;
    td->m_second = (ubyte)date.SECOND;

    return OK;
}


/*------------------------------------------------------------------*/


extern void *
MQX_malloc(ubyte4 size)
{

    return _mem_alloc_zero(size);

}


/*------------------------------------------------------------------*/


void MQX_free(void *memoryBlockPtr)
{
        (void)_mem_free(memoryBlockPtr);
}



#endif /* __MQX_RTOS__ */


